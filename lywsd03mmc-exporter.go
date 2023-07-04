// lywsd03mmc-exporter - a Prometheus exporter for the LYWSD03MMC BLE thermometer

// Copyright (C) 2020 Leah Neukirchen <leah@vuxu.org>
// Licensed under the terms of the MIT license, see LICENSE.

package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-ble/ble"
	"github.com/go-ble/ble/examples/lib/dev"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/pschlump/aesccm"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	tempGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "thermometer",
			Name:      "temperature_celsius",
			Help:      "Temperature in Celsius.",
		},
		[]string{
			"sensor",
			"mac",
		},
	)
	humGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "thermometer",
			Name:      "humidity_ratio",
			Help:      "Humidity in percent.",
		},
		[]string{
			"sensor",
			"mac",
		},
	)
	batteryGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "thermometer",
			Name:      "battery_ratio",
			Help:      "Battery in percent.",
		},
		[]string{
			"sensor",
			"mac",
		},
	)
	voltGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "thermometer",
			Name:      "battery_volts",
			Help:      "Battery in Volt.",
		},
		[]string{
			"sensor",
			"mac",
		},
	)
	frameGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "thermometer",
			Name:      "frame_current",
			Help:      "Current frame number.",
		},
		[]string{
			"sensor",
			"mac",
		},
	)
	rssiGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "thermometer",
			Name:      "rssi_dbm",
			Help:      "Received Signal Strength Indication.",
		},
		[]string{
			"sensor",
			"mac",
		},
	)
)

const Sensor = "LYWSD03MMC"
const TelinkVendorPrefix = "a4:c1:38"

var EnvironmentalSensingUUID = ble.UUID16(0x181a)
var XiaomiIncUUID = ble.UUID16(0xfe95)

const ExpiryAtc = 2.5 * 10 * time.Second
const ExpiryStock = 2.5 * 10 * time.Minute
const ExpiryConn = 2.5 * 10 * time.Second

var expirers = make(map[string]*time.Timer)
var expirersLock sync.Mutex

func bump(mac string, expiry time.Duration) {
	expirersLock.Lock()
	if t, ok := expirers[mac]; ok {
		t.Reset(expiry)
	} else {
		expirers[mac] = time.AfterFunc(expiry, func() {
			fmt.Printf("expiring %s\n", mac)

			expirersLock.Lock()
			expirers[mac].Reset(expiry)
			expirersLock.Unlock()
			cancel()
			initContext()
		})
	}
	expirersLock.Unlock()
}

func macWithColons(mac string) string {
	return strings.ToUpper(fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		mac[0:2],
		mac[2:4],
		mac[4:6],
		mac[6:8],
		mac[8:10],
		mac[10:12]))
}

func macWithoutColons(mac string) string {
	return strings.ReplaceAll(strings.ToUpper(mac), ":", "")
}

var decryptionKeys = make(map[string][]byte)

func decryptKey(key, nonce, data []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ccm, err := aesccm.NewCCM(cipher, 4, 12)
	if err != nil {
		panic(err)
	}

	var Aad = []byte{0x11}

	dst, err := ccm.Open([]byte{}, nonce, data, Aad)
	if err != nil {
		panic(err)
	}
	return dst
}

func parseData(data []byte, frameMac string, rssi int) {
	if len(data) < 11+3+4 {
		return
	}

	mac := fmt.Sprintf("%X", []byte{
		data[10], data[9], data[8], data[7], data[6], data[5],
	})

	if mac != frameMac {
		return
	}

	key, ok := decryptionKeys[mac]
	if !ok {
		logger.Infof("no key for MAC %s, skipped\n", mac)
		return
	}

	var ciphertext []byte
	ciphertext = append(ciphertext, data[11:len(data)-7]...) // payload
	ciphertext = append(ciphertext, data[len(data)-4:]...)   // token

	var nonce []byte
	nonce = append(nonce, data[5:11]...)                    // reverse MAC
	nonce = append(nonce, data[2:5]...)                     // sensor type
	nonce = append(nonce, data[len(data)-7:len(data)-4]...) // counter

	bump(mac, ExpiryStock)

	dst := decryptKey(key[:], nonce, data)

	switch dst[0] {
	case 0x04:
		temp := float64(binary.LittleEndian.Uint16(dst[3:5])) / 10.0
		reportTemperature(mac, temp)
		logger.Debugf("temperature for %s from advertisement: %f", mac, temp)
	case 0x06:
		humidity := float64(binary.LittleEndian.Uint16(dst[3:5])) / 10.0
		reportHumidity(mac, humidity)
		logger.Debugf("humidity for %s from advertisement: %f", mac, humidity)
	case 0x0A:
		// XXX always 100%?
		batteryPercentage := float64(dst[3])
		reportBatteryPercent(mac, batteryPercentage)
		logger.Debugf("battery percent for %s from advertisement: %f", mac, batteryPercentage)
	}
	rssiGauge.WithLabelValues(Sensor, mac).Set(float64(rssi))
}

func decodeSign(i uint16) int {
	if i < 32768 {
		return int(i)
	} else {
		return int(i) - 65536
	}
}

func registerData(data []byte, frameMac string, rssi int) {
	if len(data) != 13 {
		return
	}

	mac := fmt.Sprintf("%X", data[0:6])

	if mac != frameMac {
		return
	}

	temp := float64(decodeSign(binary.BigEndian.Uint16(data[6:8]))) / 10.0
	humidity := float64(data[8])
	batPercentage := float64(data[9])
	batVoltage := float64(binary.BigEndian.Uint16(data[10:12])) / 1000.0
	frame := float64(data[12])

	bump(mac, ExpiryAtc)

	reportTemperature(mac, temp)
	reportHumidity(mac, humidity)
	reportBatteryPercent(mac, batPercentage)
	reportVoltage(mac, batVoltage)

	logger.Debugf("metric for %s from advertisement: temperature %f, humidity %f, battery percent %f, battery voltage %f",
		mac, temp, humidity, batPercentage, batVoltage)

	frameGauge.WithLabelValues(Sensor, mac).Set(frame)
	rssiGauge.WithLabelValues(Sensor, mac).Set(float64(rssi))
}

func advHandler(a ble.Advertisement) {
	mac := strings.ReplaceAll(strings.ToUpper(a.Addr().String()), ":", "")

	for _, sd := range a.ServiceData() {
		if sd.UUID.Equal(EnvironmentalSensingUUID) {
			registerData(sd.Data, mac, a.RSSI())
		}
		if sd.UUID.Equal(XiaomiIncUUID) {
			parseData(sd.Data, mac, a.RSSI())
		}
	}
}

func loadKeys(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, " ", 2)
		if len(fields[0]) != 12 || len(fields[1]) != 32 {
			logger.Warnf("invalid config line, ignored: %s", line)
			continue
		}
		mac := fields[0]
		key, err := hex.DecodeString(fields[1])
		if err != nil {
			logger.Warnf("invalid config line, ignored: %s", line)
			continue
		}
		decryptionKeys[mac] = key
	}
}

func reportTemperature(mac string, temp float64) {
	tempGauge.WithLabelValues(Sensor, mac).Set(temp)
	logger.Debugf("%s thermometer_temperature_celsius %.1f\n", mac, temp)
}

func reportHumidity(mac string, hum float64) {
	humGauge.WithLabelValues(Sensor, mac).Set(hum)
	logger.Debugf("%s thermometer_humidity_ratio %.0f\n", mac, hum)
}

func reportVoltage(mac string, batv float64) {
	voltGauge.WithLabelValues(Sensor, mac).Set(batv)
	logger.Debugf("%s thermometer_battery_volts %.3f\n", mac, batv)
}

func reportBatteryPercent(mac string, batp float64) {
	batteryGauge.WithLabelValues(Sensor, mac).Set(batp)
	logger.Debugf("%s thermometer_battery_ratio %.0f\n", mac, batp)
}

func decodeStockCharacteristic(mac string) func(req []byte) {
	return func(req []byte) {
		temp := float64(int(binary.LittleEndian.Uint16(req[0:2]))) / 100.0
		humidity := float64(req[2])
		batVoltage := float64(int(binary.LittleEndian.Uint16(req[3:5]))) / 1000.0

		bump(mac, ExpiryConn)

		reportTemperature(mac, temp)
		reportHumidity(mac, humidity)
		reportVoltage(mac, batVoltage)
		logger.Debugf("metric for %s from ble client: temperature %f, humidity %f, battery voltage %f",
			mac, temp, humidity, batVoltage)
	}
}

func decodeAtcTemp(mac string) func(req []byte) {
	return func(req []byte) {
		temp := float64(decodeSign(binary.LittleEndian.Uint16(req[0:2]))) / 10.0
		bump(mac, ExpiryConn)
		reportTemperature(mac, temp)
		logger.Debugf("temperature for %s from ble client: %f", mac, temp)
	}
}

func decodeAtcHumidity(mac string) func(req []byte) {
	return func(req []byte) {
		humidity := float64(binary.LittleEndian.Uint16(req[0:2])) / 100.0
		bump(mac, ExpiryConn)
		reportHumidity(mac, humidity)
		logger.Debugf("humidity for %s from ble client: %f", mac, humidity)
	}
}

func decodeAtcBattery(mac string) func(req []byte) {
	return func(req []byte) {
		batteryPercent := float64(req[0])
		bump(mac, ExpiryConn)
		reportBatteryPercent(mac, batteryPercent)
		logger.Debugf("battery percentage for %s from ble client: %f", mac, batteryPercent)
	}
}

func pollData(mac string) {
	mac = macWithoutColons(mac)

	ctx := ble.WithSigHandler(context.WithTimeout(context.Background(), 50*time.Second))
	client, err := ble.Dial(ctx, ble.NewAddr(macWithColons(mac)))
	if err != nil {
		panic(err)
	}
	profile, err := client.DiscoverProfile(true)
	if err != nil {
		panic(err)
	}

	// code for stock hardware
	clientCharacteristicConfiguration := ble.MustParse("00002902-0000-1000-8000-00805f9b34fb")
	if c := profile.FindCharacteristic(ble.NewCharacteristic(clientCharacteristicConfiguration)); c != nil {
		b := []byte{0x01, 0x00}
		err := client.WriteCharacteristic(c, b, false)
		if err != nil {
			panic(err)
		}
	}

	subscribeCharacteristic := func(uuid ble.UUID, handler ble.NotificationHandler) {
		if c := profile.FindCharacteristic(ble.NewCharacteristic(uuid)); c != nil {
			err := client.Subscribe(c, false, handler)
			if err != nil {
				panic(err)
			}
		}
	}

	stockDataCharacteristic := ble.MustParse("ebe0ccc1-7a0a-4b0c-8a1a-6ff2997da3a6")
	subscribeCharacteristic(stockDataCharacteristic, decodeStockCharacteristic(mac))
	// code for custom hardware
	batteryServiceBatteryLevel := ble.UUID16(0x2a19)
	subscribeCharacteristic(batteryServiceBatteryLevel, decodeAtcBattery(mac))
	environmentalSensingTemperatureCelsius := ble.UUID16(0x2a1f)
	subscribeCharacteristic(environmentalSensingTemperatureCelsius, decodeAtcTemp(mac))
	environmentalSensingHumidity := ble.UUID16(0x2a6f)
	subscribeCharacteristic(environmentalSensingHumidity, decodeAtcHumidity(mac))
}

var logger *zap.SugaredLogger

var globalCtx context.Context
var cancel context.CancelFunc

func initContext() {
	globalCtx, cancel = context.WithCancel(context.TODO())
}

func main() {
	config := flag.String("k", "", "load keys from `file`")
	listenAddr := flag.String("l", ":9265", "listen on `addr`")
	deviceID := flag.Int("i", 0, "use device hci`N`")
	level := flag.String("log-level", "info", "log level")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [FLAGS...] [MACS TO POLL...]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *config != "" {
		loadKeys(*config)
	}

	c := zap.NewProductionConfig()
	c.Encoding = "console"
	c.Level, _ = zap.ParseAtomicLevel(*level)
	c.EncoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
	l, _ := c.Build()
	logger = l.Sugar()

	device, err := dev.NewDevice("default", ble.OptDeviceID(*deviceID))
	if err != nil {
		panic(err)
	}

	ble.SetDefaultDevice(device)

	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><title>lywsd03mmc-exporter</title></head><body><h1>lywsd03mmc-exporter</h1><p><a href="/metrics">Metrics</a></p></body></html>`))
		})
		http.Handle("/metrics", promhttp.Handler())
		logger.Infof("Prometheus metrics listening on %s", *listenAddr)
		err := http.ListenAndServe(*listenAddr, nil)
		if err != http.ErrServerClosed {
			panic(err)
		}
	}()

	for _, mac := range flag.Args() {
		go pollData(mac)
	}

	initContext()
	ctx := ble.WithSigHandler(globalCtx, nil)

	telinkVendorFilter := func(a ble.Advertisement) bool {
		return strings.HasPrefix(a.Addr().String(), TelinkVendorPrefix)
	}
	for {
		err = ble.Scan(ctx, true, advHandler, telinkVendorFilter)
		if err != nil {
			logger.Error(err)
		}
		time.Sleep(30 * time.Second)
		ctx = ble.WithSigHandler(globalCtx, nil)
	}
}
