import Foundation
#if canImport(CoreLocation)
import CoreLocation
#endif

public struct GeotaggedRadioRecord: Identifiable, Hashable, Codable {
    public let id: UUID
    public let identifier: String
    public let name: String
    public let radioType: String
    public let rssi: Int
    public let coordinate: GPSCoordinate
    public let timestamp: Double

    public init(
        id: UUID = UUID(),
        identifier: String,
        name: String,
        radioType: String,
        rssi: Int,
        coordinate: GPSCoordinate,
        timestamp: Double = Date().timeIntervalSince1970
    ) {
        self.id = id
        self.identifier = identifier
        self.name = name
        self.radioType = radioType
        self.rssi = rssi
        self.coordinate = coordinate
        self.timestamp = timestamp
    }
}

@MainActor
public final class GPSManager: NSObject, ObservableObject {
    @Published public var currentCoordinate: GPSCoordinate?
    @Published public var isLocationActive: Bool = false
    @Published public var totalDistanceMeters: Double = 0.0
    @Published public var routeBreadcrumbs: [GPSCoordinate] = []
    @Published public var geotaggedRadios: [GeotaggedRadioRecord] = []
    @Published public var locationStatusString: String = "Standby (Tactical Fix Ready)"

    #if canImport(CoreLocation)
    private var locationManager: CLLocationManager?
    #endif

    public override init() {
        super.init()
        // Initialize default tactical field coordinate (San Francisco Embarcadero / Financial District)
        let initial = GPSCoordinate(
            latitude: 37.774929,
            longitude: -122.419416,
            altitude: 12.5,
            horizontalAccuracy: 4.2,
            speed: 1.2
        )
        self.currentCoordinate = initial
        self.routeBreadcrumbs.append(initial)
    }

    public func startLocationServices() {
        guard !isLocationActive else { return }
        isLocationActive = true
        locationStatusString = "Active GPS Lock (High Precision)"

        #if canImport(CoreLocation)
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            let manager = CLLocationManager()
            manager.delegate = self
            manager.desiredAccuracy = kCLLocationAccuracyBestForNavigation
            manager.distanceFilter = 2.0 // meters
            #if os(iOS)
            manager.requestWhenInUseAuthorization()
            #endif
            manager.startUpdatingLocation()
            self.locationManager = manager
        }
        #endif
    }

    public func stopLocationServices() {
        isLocationActive = false
        locationStatusString = "GPS Standby"
        #if canImport(CoreLocation)
        locationManager?.stopUpdatingLocation()
        #endif
    }

    public func stampPacketLocation() -> GPSCoordinate {
        if let current = currentCoordinate {
            // If real location services are active and accurate, preserve true hardware telemetry
            if isLocationActive && current.horizontalAccuracy > 0 && current.horizontalAccuracy < 100.0 {
                return current
            }
            // Apply micro-jitter only for simulated tactical walk when hardware GPS is not active
            let jitterLat = (Double.random(in: -5...5) * 0.00001)
            let jitterLon = (Double.random(in: -5...5) * 0.00001)
            let stamped = GPSCoordinate(
                latitude: current.latitude + jitterLat,
                longitude: current.longitude + jitterLon,
                altitude: current.altitude,
                horizontalAccuracy: current.horizontalAccuracy,
                speed: current.speed,
                timestamp: Date().timeIntervalSince1970
            )
            return stamped
        }

        return GPSCoordinate(latitude: 37.7749, longitude: -122.4194)
    }

    public func tagRadio(identifier: String, name: String, radioType: String, rssi: Int) {
        let coord = stampPacketLocation()
        // Deduplicate or update latest fix
        if let idx = geotaggedRadios.firstIndex(where: { $0.identifier == identifier }) {
            geotaggedRadios[idx] = GeotaggedRadioRecord(
                id: geotaggedRadios[idx].id,
                identifier: identifier,
                name: name,
                radioType: radioType,
                rssi: rssi,
                coordinate: coord
            )
        } else {
            let record = GeotaggedRadioRecord(
                identifier: identifier,
                name: name,
                radioType: radioType,
                rssi: rssi,
                coordinate: coord
            )
            geotaggedRadios.insert(record, at: 0)
            if geotaggedRadios.count > 500 {
                geotaggedRadios.removeLast(geotaggedRadios.count - 500)
            }
        }
    }

    private func haversineDistance(from: GPSCoordinate, to: GPSCoordinate) -> Double {
        let r = 6371000.0 // Earth radius in meters
        let dLat = (to.latitude - from.latitude) * .pi / 180.0
        let dLon = (to.longitude - from.longitude) * .pi / 180.0
        let lat1 = from.latitude * .pi / 180.0
        let lat2 = to.latitude * .pi / 180.0

        let a = sin(dLat / 2.0) * sin(dLat / 2.0) +
                cos(lat1) * cos(lat2) *
                sin(dLon / 2.0) * sin(dLon / 2.0)
        let c = 2.0 * atan2(sqrt(a), sqrt(max(0.0, 1.0 - a)))
        return r * c
    }
}

#if canImport(CoreLocation)
extension GPSManager: CLLocationManagerDelegate {
    public func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        #if os(iOS) || os(macOS)
        let status: CLAuthorizationStatus
        if #available(iOS 14.0, macOS 11.0, *) {
            status = manager.authorizationStatus
        } else {
            status = CLLocationManager.authorizationStatus()
        }
        DispatchQueue.main.async { [weak self] in
            switch status {
            case .denied, .restricted:
                self?.isLocationActive = false
                self?.locationStatusString = "Location Permission Denied (Running Synthetic Tactical Coordinates)"
            case .authorizedAlways, .authorizedWhenInUse:
                self?.isLocationActive = true
                self?.locationStatusString = "Active GPS Lock (High Precision)"
                manager.startUpdatingLocation()
            case .notDetermined:
                self?.locationStatusString = "GPS Standby (Awaiting Authorization)"
            @unknown default:
                break
            }
        }
        #endif
    }

    public func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        guard let loc = locations.last else { return }
        guard loc.coordinate.latitude.isFinite && loc.coordinate.longitude.isFinite && !loc.coordinate.latitude.isNaN && !loc.coordinate.longitude.isNaN else { return }

        let newCoord = GPSCoordinate(
            latitude: loc.coordinate.latitude,
            longitude: loc.coordinate.longitude,
            altitude: loc.altitude,
            horizontalAccuracy: loc.horizontalAccuracy,
            speed: max(0.0, loc.speed),
            timestamp: loc.timestamp.timeIntervalSince1970
        )

        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            if let prev = self.currentCoordinate {
                let dist = self.haversineDistance(from: prev, to: newCoord)
                if dist > 1.0 && dist < 50000.0 {
                    self.totalDistanceMeters += dist
                }
            }
            self.currentCoordinate = newCoord
            self.routeBreadcrumbs.append(newCoord)
            if self.routeBreadcrumbs.count > 1000 {
                self.routeBreadcrumbs.removeFirst(100)
            }
        }
    }

    public func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        DispatchQueue.main.async { [weak self] in
            self?.locationStatusString = "GPS Fix Deferred: \(error.localizedDescription)"
        }
    }
}
#endif
