/*
 * *****************************************************************************************************************************
 * Copyright 2019-2020 NXP.
 * NXP Confidential. This software is owned or controlled by NXP and may only be used strictly in accordance with the applicable license terms.
 * By expressly accepting such terms or by downloading, installing, activating and/or otherwise using the software, you are agreeing that you have read, and that you agree to comply with and are bound by, such license terms.
 * If you do not agree to be bound by the applicable license terms, then you may not retain, install, activate or otherwise use the software.
 * ********************************************************************************************************************************
 *
 */

package com.nxp.sampletaplinx;


import android.app.Activity;
import android.content.Intent;
import android.graphics.Point;
import android.os.Bundle;
import android.os.Handler;
import android.view.Display;
import android.widget.ImageView;

import com.nxp.mifaresdksample.R;

/**
 * This is the launcher activity of the Application
 */
public class SplashActivity extends Activity {

    /** Splash screen timer. */
    private static final int SPLASH_TIME_OUT = 1500;

    @Override
    protected void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_splash);
        initializeUI();
        new Handler().postDelayed(new Runnable() {

            @Override
            public void run() {
                Intent i = new Intent(getApplicationContext(), MainActivity.class);
                startActivity(i);

                finish();
            }
        }, SPLASH_TIME_OUT);
    }

    /**
     * Initializing the UI thread.
     */
    private void initializeUI() {
        Display display = getWindowManager().getDefaultDisplay();
        Point size = new Point();
        display.getSize(size);

        ImageView IVTapLinxLogo = findViewById(R.id.imgTapLinx);
        IVTapLinxLogo.getLayoutParams().width = (size.x);
        IVTapLinxLogo.getLayoutParams().height = (size.y);
    }
}
