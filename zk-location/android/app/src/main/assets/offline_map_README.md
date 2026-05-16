Offline map tiles
=================

The Android app is configured to load osmdroid Mapnik tiles from APK assets
before trying any local cache or network source. Runtime network loading is
disabled in `CampusOfflineMap`, so the app only renders tiles that are packaged
under:

    Mapnik/<z>/<x>/<y>.png

For the current demo, generate zoom 14 through 18 tiles around University of
Electronic Science and Technology of China, Qingshuihe Campus:

    center_lat = 30.75316
    center_lon = 103.92829
    radius_meters = 3000
    min_zoom = 14
    max_zoom = 18

Do not create this archive from `tile.openstreetmap.org`; OSMF's tile policy
does not permit bulk downloading or offline redistribution from that service.
Use a self-hosted renderer or a tile provider that explicitly permits offline
packaging.
