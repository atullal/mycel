package dev.mycel.host

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.View
import android.webkit.JavascriptInterface
import android.webkit.MimeTypeMap
import android.webkit.WebView
import android.widget.Toast
import androidx.activity.SystemBarStyle
import androidx.activity.enableEdgeToEdge
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import java.io.File

class MainActivity : TauriActivity() {
  // Many phones drop incoming multicast unless an app holds this lock, and
  // Mycel finds people on the same Wi-Fi with mDNS (multicast).
  private var multicastLock: WifiManager.MulticastLock? = null

  // The page draws under the status and navigation bars (Android 15+ makes
  // every app edge to edge); it pads itself by these, in CSS pixels.
  @Volatile private var insetsJson = """{"top":0,"right":0,"bottom":0,"left":0,"keyboard":false}"""

  override fun onCreate(savedInstanceState: Bundle?) {
    // No scrim behind 3-button navigation: the page's own bar runs under it.
    enableEdgeToEdge(navigationBarStyle = SystemBarStyle.auto(Color.TRANSPARENT, Color.TRANSPARENT))
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) window.isNavigationBarContrastEnforced = false
    super.onCreate(savedInstanceState)
    // Notifications for new messages and calls (Android 13+ asks), then stay
    // connected in the background.
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
      ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
    ) {
      requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS)) {}
    }
    ContextCompat.startForegroundService(this, Intent(this, MycelService::class.java))
    // Reopened after being swiped away: the app (and runtime) kept running;
    // Rust gives this activity a window (src/lib.rs).
    onActivityReady()
    val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
    multicastLock = wifi?.createMulticastLock("mycel-mdns")?.apply {
      setReferenceCounted(false)
      acquire()
    }
  }

  override fun onDestroy() {
    multicastLock?.release()
    multicastLock = null
    super.onDestroy()
  }

  override fun onWebViewCreate(webView: WebView) {
    // Read once at startup by the page (apps/host/src/main.tsx)...
    webView.addJavascriptInterface(object {
      @JavascriptInterface fun insets(): String = insetsJson
    }, "MycelAndroid")
    // ...and pushed to it whenever the bars or the keyboard change.
    ViewCompat.setOnApplyWindowInsetsListener(webView) { view, insets ->
      val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
      val keyboard = insets.isVisible(WindowInsetsCompat.Type.ime())
      // The keyboard covers the navigation bar: shrink the page to end at the
      // keyboard instead, so the message composer stays in sight.
      val imeBottom = if (keyboard) insets.getInsets(WindowInsetsCompat.Type.ime()).bottom else 0
      (view.parent as? View)?.let { it.setPadding(0, 0, 0, imeBottom) }
      val d = resources.displayMetrics.density
      val bottom = if (keyboard) 0f else bars.bottom / d
      insetsJson = """{"top":${bars.top / d},"right":${bars.right / d},"bottom":$bottom,"left":${bars.left / d},"keyboard":$keyboard}"""
      (view as WebView).evaluateJavascript(
        "window.dispatchEvent(new CustomEvent('mycel-insets', { detail: $insetsJson }))", null)
      insets
    }
  }

  private external fun onActivityReady()

  /** Open a received attachment with another app. Called from Rust (src/open_file.rs). */
  @Suppress("unused")
  fun openFile(path: String) {
    runOnUiThread {
      try {
        val file = File(path)
        val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
        val type = MimeTypeMap.getSingleton().getMimeTypeFromExtension(file.extension.lowercase()) ?: "*/*"
        val view = Intent(Intent.ACTION_VIEW)
          .setDataAndType(uri, type)
          .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        startActivity(Intent.createChooser(view, file.name))
      } catch (e: ActivityNotFoundException) {
        Toast.makeText(this, "No app on this phone can open ${File(path).name}", Toast.LENGTH_LONG).show()
      } catch (e: Exception) {
        Log.w("Mycel", "attachment open failed")
        Toast.makeText(this, "Can't open ${File(path).name}", Toast.LENGTH_LONG).show()
      }
    }
  }
}
