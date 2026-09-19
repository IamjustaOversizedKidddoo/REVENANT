package com.revenant.app;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;
import java.io.File;
import java.io.FileOutputStream;
import java.util.Random;

public class MainActivity extends Activity {

    // Insecure Hardcoded API Key
    private static final String API_SECRET_KEY = "REV-MOB-SECRET-KEY-99887766";
    private static final String AUTH_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Insecure WebView Configuration (XSS)
        WebView webView = new WebView(this);
        webView.getSettings().setJavaScriptEnabled(true);
        webView.loadUrl("http://insecure-api.revenant.local/dashboard");

        // Insecure Random Number Generator (Predictable Cryptography)
        Random rng = new Random();
        int sessionToken = rng.nextInt(1000000);

        // Insecure External Storage Write
        try {
            File extDir = android.os.Environment.getExternalStorageDirectory();
            File secretFile = new File(extDir, "user_credentials.txt");
            FileOutputStream fos = new FileOutputStream(secretFile);
            fos.write(API_SECRET_KEY.getBytes());
            fos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
