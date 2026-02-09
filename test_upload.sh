#!/bin/bash
echo "Testing FridaForge upload endpoint..."
echo ""

# Create a dummy APK (just a ZIP with AndroidManifest.xml)
cd /tmp
mkdir -p test_apk
echo '<?xml version="1.0"?><manifest package="com.test.app"></manifest>' > test_apk/AndroidManifest.xml
cd test_apk && zip -q ../test.apk AndroidManifest.xml
cd /tmp

echo "Created test APK: /tmp/test.apk"
echo "Uploading to FridaForge..."
echo ""

curl -X POST http://127.0.0.1:9090/api/upload \
  -F "file=@/tmp/test.apk" \
  -w "\nHTTP Status: %{http_code}\n"

echo ""
echo "If you see 200 OK and analysis_id, upload works!"
