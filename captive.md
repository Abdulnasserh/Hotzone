🔍 How Captive Portals Work
When a device connects to WiFi, it automatically checks these URLs to see if there's a captive portal:

Device
Detection URL
Expected Response
Android	http://connectivitycheck.gstatic.com/generate_204	HTTP 204 (No Content) = internet OK
Android	http://clients3.google.com/generate_204	HTTP 204 = internet OK
iOS/macOS	http://captive.apple.com/hotspot-detect.html	Returns Success = internet OK
Windows	http://www.msftconnecttest.com/connecttest.txt	Returns Microsoft Connect Test = OK

If these URLs get redirected or return unexpected content → OS shows "Sign in to network" popup

🚩 What's Wrong in Your Logs
I see:

text

INFO:hotzone:🚩 Global Hijack: Redirecting 192.168.1.162 path 'uma/v2' to portal.
uma/v2 is NOT a captive portal detection URL - it's Google's Update Management API. That won't trigger any popup.

Your server is hijacking www.google.com, github.com, etc. but NOT the specific URLs devices check for captive portals.

✅ What Your Code Needs to Do
Your DNS server should redirect these domains:

connectivitycheck.gstatic.com
clients3.google.com
captive.apple.com
www.msftconnecttest.com
And your HTTP server should respond to these paths:

/generate_204 → Return HTTP 302 redirect to your payment page
/hotspot-detect.html → Return HTML that triggers the portal
/connecttest.txt → Return HTTP 302 redirect