import { describe, it, expect } from 'vitest';
import { LOCATION_PATTERNS } from '../../src/scanner/skill-patterns.js';

describe('Location Guard Patterns (SK-060 to SK-064)', () => {
  it('should have 5 location patterns', () => {
    expect(LOCATION_PATTERNS).toHaveLength(5);
  });

  it('all patterns should be in the location-privacy category', () => {
    for (const p of LOCATION_PATTERNS) {
      expect(p.category).toBe('location-privacy');
    }
  });

  // ── SK-060: Browser geolocation access ────────────────────

  describe('SK-060: Browser geolocation access', () => {
    const pattern = LOCATION_PATTERNS.find((p) => p.id === 'SK-060')!;

    it('exists with correct severity', () => {
      expect(pattern).toBeDefined();
      expect(pattern.severity).toBe('high');
    });

    it('detects navigator.geolocation', () => {
      expect(pattern.pattern.test('navigator.geolocation')).toBe(true);
      expect(pattern.pattern.test('navigator . geolocation')).toBe(true);
    });

    it('detects getCurrentPosition', () => {
      expect(pattern.pattern.test('getCurrentPosition(callback)')).toBe(true);
    });

    it('detects watchPosition', () => {
      expect(pattern.pattern.test('watchPosition(success, error)')).toBe(true);
    });

    it('detects GeolocationPosition interface', () => {
      expect(pattern.pattern.test('GeolocationPosition')).toBe(true);
    });

    it('detects geolocation.get/watch/clear methods', () => {
      expect(pattern.pattern.test('geolocation.getCurrentPosition')).toBe(true);
      expect(pattern.pattern.test('geolocation.watchPosition')).toBe(true);
      expect(pattern.pattern.test('geolocation.clearWatch')).toBe(true);
    });

    it('does not match unrelated code', () => {
      expect(pattern.pattern.test('import { useState } from "react"')).toBe(false);
      expect(pattern.pattern.test('const location = window.location.href')).toBe(false);
      expect(pattern.pattern.test('navigator.userAgent')).toBe(false);
    });
  });

  // ── SK-061: Mobile/native geolocation library ─────────────

  describe('SK-061: Mobile/native geolocation library', () => {
    const pattern = LOCATION_PATTERNS.find((p) => p.id === 'SK-061')!;

    it('exists with correct severity', () => {
      expect(pattern).toBeDefined();
      expect(pattern.severity).toBe('high');
    });

    it('detects React Native geolocation packages', () => {
      expect(pattern.pattern.test('@react-native-community/geolocation')).toBe(true);
      expect(pattern.pattern.test('react-native-geolocation')).toBe(true);
    });

    it('detects Expo location', () => {
      expect(pattern.pattern.test('expo-location')).toBe(true);
    });

    it('detects iOS CLLocationManager', () => {
      expect(pattern.pattern.test('CLLocationManager')).toBe(true);
      expect(pattern.pattern.test('Geolocation.requestAuthorization')).toBe(true);
    });

    it('detects Android FusedLocationProvider', () => {
      expect(pattern.pattern.test('FusedLocationProvider')).toBe(true);
      expect(pattern.pattern.test('ACCESS_FINE_LOCATION')).toBe(true);
      expect(pattern.pattern.test('ACCESS_COARSE_LOCATION')).toBe(true);
    });

    it('detects requestLocationPermission', () => {
      expect(pattern.pattern.test('requestLocationPermission()')).toBe(true);
    });

    it('does not match unrelated mobile code', () => {
      expect(pattern.pattern.test('import React from "react-native"')).toBe(false);
      expect(pattern.pattern.test('expo-camera')).toBe(false);
    });
  });

  // ── SK-062: Location data exfiltration ────────────────────

  describe('SK-062: Location data exfiltration', () => {
    const pattern = LOCATION_PATTERNS.find((p) => p.id === 'SK-062')!;

    it('exists with correct severity', () => {
      expect(pattern).toBeDefined();
      expect(pattern.severity).toBe('critical');
    });

    it('detects "send the user location"', () => {
      expect(pattern.pattern.test('send the user location to the server')).toBe(true);
    });

    it('detects "post coordinates"', () => {
      expect(pattern.pattern.test('post coordinates to the webhook')).toBe(true);
    });

    it('detects "upload gps data"', () => {
      expect(pattern.pattern.test('upload gps data to the endpoint')).toBe(true);
    });

    it('detects "transmit location"', () => {
      expect(pattern.pattern.test('transmit the location data')).toBe(true);
    });

    it('detects "track user geolocation"', () => {
      expect(pattern.pattern.test('track user geolocation')).toBe(true);
    });

    it('detects "location to https endpoint"', () => {
      expect(pattern.pattern.test('location to https://evil.com/track')).toBe(true);
    });

    it('detects "coordinates via api"', () => {
      expect(pattern.pattern.test('coordinates via api call')).toBe(true);
    });

    it('detects "share location"', () => {
      expect(pattern.pattern.test("share the user's location")).toBe(true);
    });

    it('does not match benign location references', () => {
      expect(pattern.pattern.test('display the location on a map')).toBe(false);
      expect(pattern.pattern.test('the file is located at /tmp/data')).toBe(false);
    });
  });

  // ── SK-063: IP-based geolocation lookup ───────────────────

  describe('SK-063: IP-based geolocation lookup', () => {
    const pattern = LOCATION_PATTERNS.find((p) => p.id === 'SK-063')!;

    it('exists with correct severity', () => {
      expect(pattern).toBeDefined();
      expect(pattern.severity).toBe('medium');
    });

    it('detects ip-api.com', () => {
      expect(pattern.pattern.test('fetch("https://ip-api.com/json")')).toBe(true);
    });

    it('detects ipinfo.io', () => {
      expect(pattern.pattern.test('ipinfo.io/json')).toBe(true);
    });

    it('detects MaxMind GeoIP', () => {
      expect(pattern.pattern.test('maxmind GeoLite2')).toBe(true);
      expect(pattern.pattern.test('geoip lookup')).toBe(true);
    });

    it('detects ip2location', () => {
      expect(pattern.pattern.test('ip2location database')).toBe(true);
    });

    it('detects GeoLite', () => {
      expect(pattern.pattern.test('geolite2-city database')).toBe(true);
    });

    it('detects "get location from IP"', () => {
      expect(pattern.pattern.test("get the user's location from IP")).toBe(true);
    });

    it('detects "lookup city using IP"', () => {
      expect(pattern.pattern.test('lookup city using IP address')).toBe(true);
    });

    it('does not match unrelated IP references', () => {
      expect(pattern.pattern.test('the IP address is 192.168.1.1')).toBe(false);
      expect(pattern.pattern.test('rate limit by IP')).toBe(false);
    });
  });

  // ── SK-064: Geofencing or location boundary check ─────────

  describe('SK-064: Geofencing or location boundary check', () => {
    const pattern = LOCATION_PATTERNS.find((p) => p.id === 'SK-064')!;

    it('exists with correct severity', () => {
      expect(pattern).toBeDefined();
      expect(pattern.severity).toBe('medium');
    });

    it('detects geofence/geofencing', () => {
      expect(pattern.pattern.test('set up a geofence around the area')).toBe(true);
      expect(pattern.pattern.test('geofencing enabled')).toBe(true);
    });

    it('detects location boundary/fence/zone', () => {
      expect(pattern.pattern.test('location boundary check')).toBe(true);
      expect(pattern.pattern.test('location fence trigger')).toBe(true);
      expect(pattern.pattern.test('location zone monitoring')).toBe(true);
    });

    it('detects "within N meters of"', () => {
      expect(pattern.pattern.test('within 500 meters of the target')).toBe(true);
      expect(pattern.pattern.test('within 2 miles of the store')).toBe(true);
      expect(pattern.pattern.test('within 5km of headquarters')).toBe(true);
    });

    it('detects haversine/vincenty formulas', () => {
      expect(pattern.pattern.test('haversine distance calculation')).toBe(true);
      expect(pattern.pattern.test('vincenty formula')).toBe(true);
    });

    it('detects H3 cell references', () => {
      expect(pattern.pattern.test('h3 cell index resolution 7')).toBe(true);
      expect(pattern.pattern.test('h3 boundary lookup')).toBe(true);
    });

    it('detects enter/exit geofence', () => {
      expect(pattern.pattern.test('entering the geofence')).toBe(true);
      expect(pattern.pattern.test('exited the fence perimeter')).toBe(true);
      expect(pattern.pattern.test('crossed the geofence')).toBe(true);
    });

    it('does not match unrelated boundary references', () => {
      expect(pattern.pattern.test('the function boundary is clear')).toBe(false);
      expect(pattern.pattern.test('CSS border-radius: 8px')).toBe(false);
    });
  });
});
