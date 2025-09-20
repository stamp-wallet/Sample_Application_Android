/*
 * *****************************************************************************************************************************
 * Copyright 2013-2025 NXP.
 * NXP Confidential. This software is owned or controlled by NXP and may only be used strictly in accordance with the applicable license terms.
 * By expressly accepting such terms or by downloading, installing, activating and/or otherwise using the software, you are agreeing that you have read, and that you agree to comply with and are bound by, such license terms.
 * If you do not agree to be bound by the applicable license terms, then you may not retain, install, activate or otherwise use the software.
 * ********************************************************************************************************************************
 *
 */


package com.nxp.sampletaplinx;

import static com.nxp.sampletaplinx.Constants.ALIAS_DEFAULT_FF;
import static com.nxp.sampletaplinx.Constants.ALIAS_KEY_2KTDES;
import static com.nxp.sampletaplinx.Constants.ALIAS_KEY_2KTDES_ULC;
import static com.nxp.sampletaplinx.Constants.ALIAS_KEY_AES128;
import static com.nxp.sampletaplinx.Constants.ALIAS_KEY_AES128_ZEROES;
import static com.nxp.sampletaplinx.Constants.EMPTY_SPACE;
import static com.nxp.sampletaplinx.Constants.EXTRA_KEYS_STORED_FLAG;
import static com.nxp.sampletaplinx.Constants.KEY_AES128_DEFAULT;
import static com.nxp.sampletaplinx.Constants.KEY_APP_MASTER;
import static com.nxp.sampletaplinx.Constants.PRINT;
import static com.nxp.sampletaplinx.Constants.STORAGE_PERMISSION_WRITE;
import static com.nxp.sampletaplinx.Constants.TAG;
import static com.nxp.sampletaplinx.Constants.TOAST;
import static com.nxp.sampletaplinx.Constants.TOAST_PRINT;
import static com.nxp.sampletaplinx.Constants.bytesKey;
import static com.nxp.sampletaplinx.Constants.cipher;
import static com.nxp.sampletaplinx.Constants.default_ff_key;
import static com.nxp.sampletaplinx.Constants.default_zeroes_key;
import static com.nxp.sampletaplinx.Constants.iv;
import static com.nxp.sampletaplinx.Constants.objKEY_2KTDES;
import static com.nxp.sampletaplinx.Constants.objKEY_2KTDES_ULC;
import static com.nxp.sampletaplinx.Constants.objKEY_AES128;
import static com.nxp.sampletaplinx.Constants.packageKey;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.Activity;
import android.app.ActivityManager;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Point;
import android.graphics.Typeface;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.MifareClassic;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.preference.PreferenceManager;
import android.text.Html;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.Display;
import android.view.Gravity;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AnimationUtils;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;
import android.widget.EditText;

import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.nxp.mifaresdksample.R;
import com.nxp.nfclib.CardType;
import com.nxp.nfclib.NxpNfcLib;
import com.nxp.nfclib.classic.ClassicFactory;
import com.nxp.nfclib.defaultimpl.KeyData;
import com.nxp.nfclib.desfire.DESFireFactory;
import com.nxp.nfclib.desfire.IDESFireEV2;
import com.nxp.nfclib.desfire.IDESFireEV3;
import com.nxp.nfclib.desfire.IDESFireEV3C;
import com.nxp.nfclib.desfire.IDESFireLight;
import com.nxp.nfclib.desfire.IMIFAREIdentity;
import com.nxp.nfclib.exceptions.NxpNfcLibException;
import com.nxp.nfclib.icode.ICodeFactory;
import com.nxp.nfclib.ntag.NTagFactory;
import com.nxp.nfclib.plus.IPlus;
import com.nxp.nfclib.plus.IPlusEV1SL0;
import com.nxp.nfclib.plus.IPlusEV1SL1;
import com.nxp.nfclib.plus.IPlusEV1SL3;
import com.nxp.nfclib.plus.IPlusSL0;
import com.nxp.nfclib.plus.IPlusSL1;
import com.nxp.nfclib.plus.IPlusSL3;
import com.nxp.nfclib.plus.PlusFactory;
import com.nxp.nfclib.plus.PlusSL1Factory;
import com.nxp.nfclib.ultralight.UltralightFactory;
import com.nxp.nfclib.utils.NxpLogUtils;
import com.nxp.nfclib.utils.Utilities;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Collectors;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;



/**
 * MainActivity has the business logic to initialize the taplinx library and use it for
 * identification of the cards
 */
public class MainActivity extends Activity {
    /**
     * NxpNfclib instance.
     */
    private NxpNfcLib libInstance = null;
    /**
     * text view instance.
     */
    private TextView information_textView = null;
    /**
     * Image view instance.
     */
    private ImageView logoAndCardImageView = null;

    private ImageView tapTagImageView;


    private final StringBuilder stringBuilder = new StringBuilder();

    static Object mString;

    CardLogic mCardLogic;

    @RequiresApi(api = Build.VERSION_CODES.N)
    @Override
    protected void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);


        setContentView(R.layout.activity_main);

        tapTagImageView = findViewById(R.id.tap_tag_image);
        logoAndCardImageView = findViewById(R.id.nxp_logo_card_snap);

        boolean readPermission = (ContextCompat.checkSelfPermission(MainActivity.this,
                Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED);

        if (!readPermission) {
            ActivityCompat.requestPermissions(MainActivity.this,
                    new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE},
                    STORAGE_PERMISSION_WRITE
            );
        }

        mCardLogic = CardLogic.getInstance();

        /* Initialize the library and register to this activity */
        initializeLibrary();

        initializeKeys();

        /* Initialize the Cipher and init vector of 16 bytes with 0xCD */
        initializeCipherinitVector();

        /* Get text view handle to be used further */
        initializeView();

        BottomNavigationView bottomNavigationView = findViewById(
                R.id.bottom_navigation);
        bottomNavigationView.setOnNavigationItemSelectedListener(
                new BottomNavigationView.OnNavigationItemSelectedListener() {
                    @Override
                    public boolean onNavigationItemSelected(@NonNull MenuItem item) {
                // Starting with Android Gradle Plugin 8.0.0, by default, resources (e.g. R.id. ...)
                // are no longer declared final (i.e. constant expressions) for optimized build speed,
                // which is a prerequisite to be used in switch statements.
                // So If block is used instead of switch.
                        int itemId = item.getItemId();
                        if (itemId == R.id.text_write) {//An intent is an oject that provides run time binding between
                            // two components
                            Intent intent = new Intent(MainActivity.this,
                                    WriteActivity.class);
                            //this is used as activity class is subclass of Context
                            startActivity(intent);
                            finish();
                        } else if (itemId == R.id.text_about) {
                            AlertDialog.Builder alert = new AlertDialog.Builder(
                                    MainActivity.this);
                            alert.setTitle(getString(R.string.About));
                            alert.setCancelable(false);
                            String[] cards = libInstance.getSupportedCards();
                            // get TapLinx version.
                            String taplinxVersion = NxpNfcLib.getTaplinxVersion();
                            String message = getString(R.string.about_text);

                            message = Html.fromHtml(message).toString();
                            String alertMessage = message + "\n";

                            alertMessage += "\n";
                            String appVer = getApplicationVersion();
                            if (appVer != null) {
                                alertMessage += getString(R.string.Application_Version) + appVer
                                        + "\n";
                            }
                            //Display the current version of TapLinx library
                            alertMessage += "\n" + getString(R.string.TapLinx_Version)
                                    + taplinxVersion + "\n";

                            alertMessage += "\n" + getString(R.string.Supported_Cards)
                                    + Arrays.toString(cards) + "\n";

                            alert.setMessage(alertMessage);
                            alert.setIcon(R.mipmap.ic_launcher);
                            alert.setPositiveButton("Ok",
                                    new DialogInterface.OnClickListener() {
                                        public void onClick(final DialogInterface dialog,
                                                            final int whichButton) {

                                        }
                                    });
                            alert.show();
                        }
                        return false;
                    }
                });


    }

    private void initializeKeys() {
        KeyInfoProvider infoProvider = KeyInfoProvider.getInstance(getApplicationContext());

        SharedPreferences sharedPrefs = getPreferences(Context.MODE_PRIVATE);
        boolean keysStoredFlag = sharedPrefs.getBoolean(EXTRA_KEYS_STORED_FLAG, false);
        if (!keysStoredFlag) {
            //Set Key stores the key in persistent storage, this method can be called only once
            // if key for a given alias does not change.
            byte[] ulc24Keys = new byte[24];
            System.arraycopy(SampleAppKeys.KEY_2KTDES_ULC, 0, ulc24Keys, 0,
                    SampleAppKeys.KEY_2KTDES_ULC.length);
            System.arraycopy(SampleAppKeys.KEY_2KTDES_ULC, 0, ulc24Keys,
                    SampleAppKeys.KEY_2KTDES_ULC.length, 8);
            infoProvider.setKey(ALIAS_KEY_2KTDES_ULC, SampleAppKeys.EnumKeyType.EnumDESKey,
                    ulc24Keys);

            infoProvider.setKey(ALIAS_KEY_2KTDES, SampleAppKeys.EnumKeyType.EnumDESKey,
                    SampleAppKeys.KEY_2KTDES);
            infoProvider.setKey(ALIAS_KEY_AES128, SampleAppKeys.EnumKeyType.EnumAESKey,
                    SampleAppKeys.KEY_AES128);
            infoProvider.setKey(ALIAS_KEY_AES128_ZEROES, SampleAppKeys.EnumKeyType.EnumAESKey,
                    SampleAppKeys.KEY_AES128_ZEROS);
            infoProvider.setKey(ALIAS_DEFAULT_FF, SampleAppKeys.EnumKeyType.EnumMifareKey,
                    SampleAppKeys.KEY_DEFAULT_FF);

            sharedPrefs.edit().putBoolean(EXTRA_KEYS_STORED_FLAG, true).apply();
            //If you want to store a new key after key initialization above, kindly reset the
            // flag EXTRA_KEYS_STORED_FLAG to false in shared preferences.
        }
        try {

            objKEY_2KTDES_ULC = infoProvider.getKey(ALIAS_KEY_2KTDES_ULC,
                    SampleAppKeys.EnumKeyType.EnumDESKey);
            objKEY_2KTDES = infoProvider.getKey(ALIAS_KEY_2KTDES,
                    SampleAppKeys.EnumKeyType.EnumDESKey);
            objKEY_AES128 = infoProvider.getKey(ALIAS_KEY_AES128,
                    SampleAppKeys.EnumKeyType.EnumAESKey);
            default_zeroes_key = infoProvider.getKey(ALIAS_KEY_AES128_ZEROES,
                    SampleAppKeys.EnumKeyType.EnumAESKey);
            default_ff_key = infoProvider.getMifareKey(ALIAS_DEFAULT_FF);
        } catch (Exception e) {
            ((ActivityManager) Objects.requireNonNull(
                    MainActivity.this.getSystemService(ACTIVITY_SERVICE)))
                    .clearApplicationUserData();
        }
    }

    /**
     * Initializing the widget, and Get text view handle to be used further.
     */
    private void initializeView() {
        /* Get text view handle to be used further */
        information_textView = findViewById(R.id.info_textview);
        information_textView.setMovementMethod(new ScrollingMovementMethod());
        Typeface face = Typeface.SANS_SERIF;
        information_textView.setTypeface(face);
        information_textView.setTextColor(Color.BLACK);

        /* Get image view handle to be used further */
        logoAndCardImageView = findViewById(R.id.nxp_logo_card_snap);

    }

    /**
     * Initialize the library and register to this activity.
     */
    @TargetApi(19)
    private void initializeLibrary() {
        libInstance = NxpNfcLib.getInstance();
        try {
            libInstance.registerActivity(this, "7e4cec107f67a602e9ef59c30a7b6375");
        } catch (NxpNfcLibException ex) {
            showMessage(ex.getMessage(), TOAST);
        } catch (Exception e) {
            // do nothing added to handle the crash if any
        }
    }

    /**
     * Initialize the Cipher and init vector of 16 bytes with 0xCD.
     */
    private void initializeCipherinitVector() {
        /* Initialize the Cipher */
        try {
            cipher = Cipher.getInstance("AES/CBC/NoPadding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        /* set Application Master Key */
        bytesKey = KEY_APP_MASTER.getBytes();

        /* Initialize init vector of 16 bytes with 0xCD. It could be anything */
        byte[] ivSpec = new byte[16];
        Arrays.fill(ivSpec, (byte) 0xCD);
        iv = new IvParameterSpec(ivSpec);
    }

    /**
     * (non-Javadoc).
     *
     * @param intent NFC intent from the android framework.
     *               // @see android.app.Activity#onNewIntent(android.content.Intent)
     */
    @Override
    public void onNewIntent(final Intent intent) {
        stringBuilder.delete(0, stringBuilder.length());
        final Bundle extras = intent.getExtras();
        mString = Objects.requireNonNull(extras).get("android.nfc.extra.TAG");
        logoAndCardImageView.setVisibility(View.VISIBLE);
        Log.e("NxpNfcLibException","sushil");
        try {
            cardLogic(intent);
            super.onNewIntent(intent);
            tapTagImageView.setVisibility(View.GONE);
        } catch (Exception e) {
            Log.e("NxpNfcLibException", e.getMessage());
            showMessage(e.getMessage(), TOAST_PRINT);
        }
    }


    //This API identifies the card type and calls the specific operations
    private void cardLogic(final Intent intent) {
        CardType type = libInstance.getCardType(intent); //Get the type of the card
        if (type == CardType.UnknownCard) {
            logoAndCardImageView.setVisibility(View.INVISIBLE);
            showMessage(getString(R.string.UNKNOWN_TAG), PRINT);
            information_textView.setGravity(Gravity.CENTER);
        }
        information_textView.setText(EMPTY_SPACE);
        switch (type) {
            case MIFAREClassic: {
                if (intent.hasExtra(NfcAdapter.EXTRA_TAG)) {
                    Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
                    if (tag != null) {
                        showImageSnap(R.drawable.classic);
                        showMessage(mCardLogic.classicCardLogic(this,
                                ClassicFactory.getInstance().getClassic(
                                        MifareClassic.get(tag))), PRINT);
                    }
                }
                break;
            }
            case MIFAREClassicEV1: {
                if (intent.hasExtra(NfcAdapter.EXTRA_TAG)) {
                    Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
                    if (tag != null) {
                        showImageSnap(R.drawable.classicev1);
                        showMessage(mCardLogic.classicCardEV1Logic(this,
                                ClassicFactory.getInstance().getClassicEV1(
                                        MifareClassic.get(tag))), PRINT);
                    }
                }
                break;
            }
            case Ultralight:
                try {
                    showImageSnap(R.drawable.ultralight);
                    showMessage(mCardLogic.ultralightCardLogic(this,
                            UltralightFactory.getInstance().getUltralight(
                                    libInstance.getCustomModules())), PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case UltralightEV1_11:
            case UltralightEV1_21:
                try {
                    showImageSnap(R.drawable.ultralight_ev1);
                    showMessage(mCardLogic.ultralightEV1CardLogic(this,
                            UltralightFactory.getInstance().getUltralightEV1(
                                    libInstance.getCustomModules())), PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case UltralightC:
                try {
                    showImageSnap(R.drawable.ultralight_c);
                    showMessage(mCardLogic.ultralightcCardLogic(this,
                            UltralightFactory.getInstance().getUltralightC(
                                    libInstance.getCustomModules())), PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTag203X:
                try {
                    showImageSnap(R.drawable.ntag_p);
                    showMessage(mCardLogic.ntagCardLogic(this,
                            NTagFactory.getInstance().getNTAG203x(libInstance.getCustomModules())),
                            PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTag210:
                try {
                    showImageSnap(R.drawable.ntag_p);
                    showMessage(mCardLogic.ntagCardLogic(this,
                            NTagFactory.getInstance().getNTAG210(libInstance.getCustomModules())),
                            PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTag213:
                try {
                    showImageSnap(R.drawable.ntag_p);
                    showMessage(mCardLogic.ntagCardLogic(this,
                            NTagFactory.getInstance().getNTAG213(libInstance.getCustomModules())),
                            PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTag215:
                try {
                    showImageSnap(R.drawable.ntag_p);
                    showMessage(mCardLogic.ntagCardLogic(this,
                            NTagFactory.getInstance().getNTAG215(libInstance.getCustomModules())),
                            PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTag216:
                try {
                    showImageSnap(R.drawable.ntag_p);
                    showMessage(mCardLogic.ntagCardLogic(this,
                            NTagFactory.getInstance().getNTAG216(libInstance.getCustomModules())),
                            PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTag213F:
                try {
                    showImageSnap(R.drawable.ntag_p);
                    showMessage(mCardLogic.ntagCardLogic(this,
                            NTagFactory.getInstance().getNTAG213F(libInstance.getCustomModules())),
                            PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTag216F:
                try {
                    showImageSnap(R.drawable.ntag_p);
                    showMessage(mCardLogic.ntagCardLogic(this,
                            NTagFactory.getInstance().getNTAG216F(libInstance.getCustomModules())),
                            PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTAG223DNA:
                try {
                    showImageSnap(R.drawable.ntag_p);
                    showMessage(mCardLogic.ntagCardLogic(this,NTagFactory.getInstance().getNTAG223DNA(libInstance.getCustomModules())),PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTAG223DNAStatusDetect:
                try {
                    showImageSnap(R.drawable.ntag_p);
                    showMessage(mCardLogic.ntagCardLogic(this,NTagFactory.getInstance().getNTAG223DNAStatusDetect(libInstance.getCustomModules())),PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTAG224DNA:
                try {
                    showImageSnap(R.drawable.ntag_p);
                    showMessage(mCardLogic.ntagCardLogic(this,NTagFactory.getInstance().getNTAG224DNA(libInstance.getCustomModules())),PRINT);
                } catch (Throwable t) {
                    Log.e(TAG, t.getMessage());
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTAG224DNAStatusDetect:
                try {
                    showImageSnap(R.drawable.ntag_p);
                    showMessage(mCardLogic.ntagCardLogic(this,NTagFactory.getInstance().getNTAG224DNAStatusDetect(libInstance.getCustomModules())),PRINT);
                } catch (Throwable t) {
                    Log.e(TAG, t.getMessage());
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case MIFAREUltralightAES:
                try {
                    showImageSnap(R.drawable.ultralight_aes);
                    showMessage(mCardLogic.ultralightAESCardLogic(this, UltralightFactory.getInstance().getUltralightAES(libInstance.getCustomModules())),PRINT);
                } catch (Throwable t) {
                    Log.e(TAG, t.getMessage());
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTagI2C1K:
                try {
                    showImageSnap(R.drawable.ntag_p);
                    showMessage(mCardLogic.ntagCardLogic(this,
                            NTagFactory.getInstance().getNTAGI2C1K(libInstance.getCustomModules())),
                            PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTagI2C2K:
                try {
                    showImageSnap(R.drawable.ntag_p);
                    showMessage(mCardLogic.ntagCardLogic(this,
                            NTagFactory.getInstance().getNTAGI2C2K(libInstance.getCustomModules())),
                            PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTagI2CPlus1K:
                try {
                    showImageSnap(R.drawable.ntag_p);
                    showMessage(mCardLogic.ntagCardLogic(this,
                            NTagFactory.getInstance().getNTAGI2CPlus1K(
                                    libInstance.getCustomModules())),
                            PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTagI2CPlus2K:
                try {
                    showImageSnap(R.drawable.ntag_p);
                    showMessage(mCardLogic.ntagCardLogic(this,
                            NTagFactory.getInstance().getNTAGI2CPlus2K(
                                    libInstance.getCustomModules())),
                            PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTag210u:
                try {
                    showImageSnap(R.drawable.ntag_p);
                    showMessage(mCardLogic.ntagCardLogic(this,
                            NTagFactory.getInstance().getNTAG210u(libInstance.getCustomModules())),
                            PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTag413DNA:
                try {
                    showImageSnap(R.drawable.ntag_p);
                    showMessage(mCardLogic.ntag413CardLogic(this,
                            DESFireFactory.getInstance().getNTag413DNA(
                                    libInstance.getCustomModules())), PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTAG424DNA:
                try {
                    showImageSnap(R.drawable.ntag_p);
                    showMessage(mCardLogic.tag424DNACardLogic(this,
                            DESFireFactory.getInstance().getNTAG424DNA(
                                    libInstance.getCustomModules())), PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTAG424DNATagTamper:
                try {
                    showImageSnap(R.drawable.ntag_p);
                    showMessage(mCardLogic.tag424DNATTCardLogic(this,
                            DESFireFactory.getInstance().getNTAG424DNATT(
                                    libInstance.getCustomModules())), PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;

            case NTag213TagTamper:
                try {
                    showImageSnap(R.drawable.ntag_p);
                    showMessage(mCardLogic.ntag213TTCardLogic(this,
                            NTagFactory.getInstance().getNTAG213TagTamper(
                                    libInstance.getCustomModules())), PRINT);
                } catch (Throwable t) {
                    t.printStackTrace();
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case ICodeSLI:
                try {
                    showImageSnap(R.drawable.icode_p);
                    showMessage(mCardLogic.iCodeSLICardLogic(this,
                            ICodeFactory.getInstance().getICodeSLI(libInstance.getCustomModules())),
                            PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case ICodeSLIS:
                try {
                    showImageSnap(R.drawable.icode_p);
                    showMessage(mCardLogic.iCodeSLISCardLogic(this,
                            ICodeFactory.getInstance().getICodeSLIS(
                                    libInstance.getCustomModules())), PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case ICodeSLIL:
                try {
                    showImageSnap(R.drawable.icode_p);
                    showMessage(mCardLogic.iCodeSLILCardLogic(this,
                            ICodeFactory.getInstance().getICodeSLIL(
                                    libInstance.getCustomModules())), PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case ICodeSLIX:
                try {
                    showImageSnap(R.drawable.icode_p);
                    showMessage(mCardLogic.iCodeSLIXCardLogic(this,
                            ICodeFactory.getInstance().getICodeSLIX(
                                    libInstance.getCustomModules())), PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case ICodeSLIXS:
                try {
                    showImageSnap(R.drawable.icode_p);
                    showMessage(mCardLogic.iCodeSLIXSCardLogic(this,
                            ICodeFactory.getInstance().getICodeSLIXS(
                                    libInstance.getCustomModules())), PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case ICodeSLIXL:
                try {
                    showImageSnap(R.drawable.icode_p);
                    showMessage(mCardLogic.iCodeSLIXLCardLogic(this,
                            ICodeFactory.getInstance().getICodeSLIXL(
                                    libInstance.getCustomModules())), PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case ICodeSLIX2:
                try {
                    showImageSnap(R.drawable.icode_p);
                    showMessage(mCardLogic.iCodeSLIX2CardLogic(this,
                            ICodeFactory.getInstance().getICodeSLIX2(
                                    libInstance.getCustomModules())), PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case ICodeDNA:
                try {
                    showImageSnap(R.drawable.icode_p);
                    showMessage(mCardLogic.iCodeDNACardLogic(this,
                            ICodeFactory.getInstance().getICodeDNA(libInstance.getCustomModules())),
                            PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case DESFireEV1:
                try {
                    showImageSnap(R.drawable.desfire_ev1);
                    showMessage(mCardLogic.desfireEV1CardLogic(this,
                            DESFireFactory.getInstance().getDESFire(
                                    libInstance.getCustomModules())), PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case DESFireEV2:
                IDESFireEV2 desFireEV2 = DESFireFactory.getInstance().getDESFireEV2(
                        libInstance.getCustomModules());
                if (desFireEV2.getSubType() == IDESFireEV2.SubType.MIFAREIdentity) {
                    information_textView.setText(EMPTY_SPACE);
                    showImageSnap(R.drawable.mifare_identity);
                    stringBuilder.append(getString(R.string.Sub_Type)).append(
                            getString(R.string.Mifare_Identity));
                    IMIFAREIdentity mfID = DESFireFactory.getInstance().getMIFAREIdentity(
                            libInstance.getCustomModules());
                    byte[] fciData = mfID.selectMIFAREIdentityAppAndReturnFCI();
                    stringBuilder.append(getString(R.string.FCI_Data)).append(
                            Utilities.dumpBytes(fciData));
                    showMessage(stringBuilder.toString(), PRINT);
                } else {
                    information_textView.setText(EMPTY_SPACE);
                    showImageSnap(R.drawable.desfire_ev2);
                    showMessage(getString(R.string.Card_Detected) + getString(R.string.desfireEV2),
                            PRINT);
                    try {
                        KeyData desKeyDataDefault = new KeyData();
                        Key key = new SecretKeySpec(KEY_AES128_DEFAULT, "DESede");
                        desKeyDataDefault.setKey(key);
                        desFireEV2.getReader().connect();
                        showImageSnap(R.drawable.desfire_ev2);
                        showMessage(mCardLogic.desfireEV2CardLogic(this, desFireEV2), PRINT);
                    } catch (Throwable t) {
                        t.printStackTrace();
                        showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                    }
                }
                break;
            case DESFireEV3:
                IDESFireEV3 idesFireEV3 = DESFireFactory.getInstance().getDESFireEV3(
                        libInstance.getCustomModules());
                if (idesFireEV3.getSubType() == IDESFireEV3.SubType.MIFAREIdentity) {
                    information_textView.setText(EMPTY_SPACE);
                    showImageSnap(R.drawable.mifare_identity);
                    stringBuilder.append(getString(R.string.Sub_Type)).append(
                            getString(R.string.Mifare_Identity));
                    IMIFAREIdentity mfID = DESFireFactory.getInstance().getMIFAREIdentity(
                            libInstance.getCustomModules());
                    byte[] fciData = mfID.selectMIFAREIdentityAppAndReturnFCI();
                    stringBuilder.append(getString(R.string.FCI_Data)).append(
                            Utilities.dumpBytes(fciData));
                    showMessage(stringBuilder.toString(), PRINT);
                } else {
                    information_textView.setText(EMPTY_SPACE);
                    showImageSnap(R.drawable.desfireev3);
                    showMessage(getString(R.string.Card_Detected) +getString(R.string.desfireEV3),
                            PRINT);
                    try {
                        KeyData desKeyDataDefault = new KeyData();
                        Key key = new SecretKeySpec(KEY_AES128_DEFAULT, "DESede");
                        desKeyDataDefault.setKey(key);
                        idesFireEV3.getReader().connect();
                        showImageSnap(R.drawable.desfireev3);
                        showMessage(mCardLogic.desfireEV2CardLogic(this, idesFireEV3), PRINT);
                    } catch (Throwable t) {
                        t.printStackTrace();
                        showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                    }
                }
                break;
            case DESFireEV3C:
                IDESFireEV3C idesFireEV3C = DESFireFactory.getInstance().getDESFireEV3C(
                        libInstance.getCustomModules());
                if (idesFireEV3C.getSubType() == IDESFireEV3C.SubType.MIFAREIdentity) {
                    information_textView.setText(EMPTY_SPACE);
                    showImageSnap(R.drawable.mifare_identity);
                    stringBuilder.append(getString(R.string.Sub_Type)).append(
                            getString(R.string.Mifare_Identity));
                    IMIFAREIdentity mfID = DESFireFactory.getInstance().getMIFAREIdentity(
                            libInstance.getCustomModules());
                    byte[] fciData = mfID.selectMIFAREIdentityAppAndReturnFCI();
                    stringBuilder.append(getString(R.string.FCI_Data)).append(
                            Utilities.dumpBytes(fciData));
                    showMessage(stringBuilder.toString(), PRINT);
                } else {
                    information_textView.setText(EMPTY_SPACE);
                    showImageSnap(R.drawable.desfireev3c);
                    showMessage(getString(R.string.Card_Detected) +getString(R.string.desfireEV3C),
                            PRINT);
                    try {
                        KeyData desKeyDataDefault = new KeyData();
                        Key key = new SecretKeySpec(KEY_AES128_DEFAULT, "DESede");
                        desKeyDataDefault.setKey(key);
                        idesFireEV3C.getReader().connect();
                        showImageSnap(R.drawable.desfireev3c);
                        showMessage(mCardLogic.desfireEV2CardLogic(this, idesFireEV3C), PRINT);
                    } catch (Throwable t) {
                        t.printStackTrace();
                        showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                    }
                }
                break;

            case DESFireLight:
                IDESFireLight idesFireLight = DESFireFactory.getInstance().getDESFireLight(
                        libInstance.getCustomModules());
                try {
                    KeyData aesKeyData = new KeyData();
                    Key key = new SecretKeySpec(KEY_AES128_DEFAULT, "AES");
                    aesKeyData.setKey(key);
                    idesFireLight.getReader().connect();
                    showImageSnap(R.drawable.desfire_light);
                    showMessage(mCardLogic.desfireLightCardLogic(this, idesFireLight), PRINT);
                } catch (Throwable t) {
                    t.printStackTrace();
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case MIFAREIdentity:
                information_textView.setText(EMPTY_SPACE);
                showImageSnap(R.drawable.mifare_identity);
                showMessage(getString(R.string.Card_Detected) + getString(R.string.Mifare_Identity),
                        PRINT);
                break;
            case PlusSL0:
                information_textView.setText(EMPTY_SPACE);
                IPlusSL0 plusSL0 = PlusFactory.getInstance().getPlusSL0(
                        libInstance.getCustomModules());
                showMessage(getString(R.string.Card_Detected) + plusSL0.getType().getTagName(),
                        PRINT);
                showMessage(getString(R.string.Sub_Type) + plusSL0.getPlusType(), PRINT);

                if (plusSL0.getPlusType() == IPlus.SubType.PLUS_SE) {
                    showImageSnap(R.drawable.plusse);
                } else {
                    showImageSnap(R.drawable.plus);
                }
                // code is commented because the operations are irreversible.
                //plusSL0.writePerso(0x9000,default_ff_key); // similarly fill all the mandatory
                // keys.
                //plusSL0.commitPerso();
                showMessage(getString(R.string.No_Operations_executed_on_Plus_SL0), PRINT);
                break;
            case PlusSL1:
                information_textView.setText(EMPTY_SPACE);
                showImageSnap(R.drawable.plus);
                Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
                MifareClassic obj = MifareClassic.get(tag);
                IPlusSL1 plusSL1;
                if (obj != null) {
                    plusSL1 = PlusSL1Factory.getInstance().getPlusSL1(
                            libInstance.getCustomModules(), obj);
                    showImageSnap(R.drawable.plus);
                    showMessage(mCardLogic.plusSL1CardLogic(this, plusSL1), PRINT);
                } else {
                    plusSL1 = PlusSL1Factory.getInstance().getPlusSL1(
                            libInstance.getCustomModules());
                    showImageSnap(R.drawable.plus);
                    information_textView.setText(EMPTY_SPACE);
                    showMessage(getString(R.string.Card_Detected) + plusSL1.getType().getTagName(),
                            PRINT);
                    showMessage(getString(R.string.Plus_SL1_Operations_not_supported_on_device),
                            PRINT);
                    //sample code to switch sector to security level 3. commented because changes
                    // are irreversible.
                    //plusSL1.switchToSL3(objKEY_AES128);
                }
                break;
            case PlusSL3:
                information_textView.setText(EMPTY_SPACE);
                showMessage(getString(R.string.Card_Detected) + getString(R.string.plus),
                        PRINT);
                IPlusSL3 plusSL3 = PlusFactory.getInstance().getPlusSL3(
                        libInstance.getCustomModules());
                try {
                    plusSL3.getReader().connect();
                    if (plusSL3.getPlusType() == IPlus.SubType.PLUS_SE) {
                        showImageSnap(R.drawable.plusse);
                    } else {
                        showImageSnap(R.drawable.plus);
                    }
                    showMessage(mCardLogic.plusSL3CardLogic(this, plusSL3), PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case PlusEV1SL0:
                information_textView.setText(EMPTY_SPACE);
                showImageSnap(R.drawable.plusev1);

                IPlusEV1SL0 plusEV1SL0 = PlusFactory.getInstance().getPlusEV1SL0(
                        libInstance.getCustomModules());
                try {
                    plusEV1SL0.getReader().connect();
                    showMessage(
                            getString(R.string.Card_Detected) + plusEV1SL0.getType().getTagName(),
                            PRINT);
                    showMessage(getString(R.string.No_operations_executed_on_Plus_EV1_SL0),
                            PRINT);
                } catch (Throwable t) {
                    t.printStackTrace();
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case PlusEV1SL1:
                information_textView.setText(EMPTY_SPACE);
                showImageSnap(R.drawable.plusev1);
                tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
                obj = MifareClassic.get(tag);
                IPlusEV1SL1 plusEV1SL1;
                if (obj != null) {
                    plusEV1SL1 = PlusSL1Factory.getInstance().getPlusEV1SL1(
                            libInstance.getCustomModules());
                    showMessage(mCardLogic.plusEV1SL1CardLogic(this, plusEV1SL1), PRINT);
                } else {
                    plusEV1SL1 = PlusSL1Factory.getInstance().getPlusEV1SL1(
                            libInstance.getCustomModules());
                    showImageSnap(R.drawable.plus);
                    information_textView.setText(EMPTY_SPACE);
                    showMessage(
                            getString(R.string.Card_Detected) + plusEV1SL1.getType().getTagName(),
                            PRINT);
                    showMessage(getString(R.string.Plus_SL1_Operations_not_supported_on_device),
                            PRINT);
                }
                break;
            case PlusEV1SL3:
                IPlusEV1SL3 plusEV1SL3 = PlusFactory.getInstance().getPlusEV1SL3(
                        libInstance.getCustomModules());
                try {
                    if (!plusEV1SL3.getReader().isConnected()) {
                        plusEV1SL3.getReader().connect();
                    }
                    showImageSnap(R.drawable.plusev1);
                    showMessage(mCardLogic.plusEV1SL3CardLogic(this, plusEV1SL3), PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case UltralightNano_40:
                showMessage(getString(R.string.Card_Detected) + getString(R.string.UL_nano_40),
                        TOAST);
                try {
                    showImageSnap(R.drawable.ultralight_nano);
                    showMessage(mCardLogic.ultralightNanoCardLogic(this,
                            UltralightFactory.getInstance().getUltralightNano(
                                    libInstance.getCustomModules())), PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case UltralightNano_48:
                showMessage(getString(R.string.Card_Detected) + getString(R.string.UL_nano_48),
                        TOAST);
                try {
                    showImageSnap(R.drawable.ultralight_nano);
                    showMessage(mCardLogic.ultralightNanoCardLogic(this,
                            UltralightFactory.getInstance().getUltralightNano(
                                    libInstance.getCustomModules())), PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case MifareDUOX:
                try {
                    information_textView.setText(EMPTY_SPACE);
                    showImageSnap(R.drawable.mifare_duox);
                    showMessage(getString(R.string.Card_Detected) +getString(R.string.MifareDUOX),
                            PRINT);
                    showMessage(mCardLogic.mifareDUOXCardLogic(this,
                            DESFireFactory.getInstance().getMifareDUOX(
                                    libInstance.getCustomModules())), PRINT);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
        }
//        To save the logs to file \sdcard\NxpLogDump\logdump.xml
        NxpLogUtils.save();
    }


    @Override
    protected void onPause() {
        super.onPause();
        libInstance.stopForeGroundDispatch();
    }

    @Override
    protected void onResume() {
        super.onResume();
        libInstance.startForeGroundDispatch();
    }

    /**
     * Update the card image on the screen.
     *
     * @param cardTypeId resource image id of the card image
     */

    private void showImageSnap(final int cardTypeId) {
        Display display = getWindowManager().getDefaultDisplay();
        Point size = new Point();
        display.getSize(size);
        logoAndCardImageView.getLayoutParams().width = (size.x * 2) / 3;
        logoAndCardImageView.getLayoutParams().height = size.y / 3;
        Handler mHandler = new Handler();
        mHandler.postDelayed(new Runnable() {
            public void run() {
                logoAndCardImageView.setImageResource(cardTypeId);
                logoAndCardImageView.startAnimation(
                        AnimationUtils.loadAnimation(getApplicationContext(), R.anim.zoomnrotate));
            }
        }, 1250);
        logoAndCardImageView.setImageResource(R.drawable.product_overview);
        logoAndCardImageView.startAnimation(AnimationUtils.loadAnimation(this, R.anim.rotate));
        LinearLayout.LayoutParams layoutParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT);
        layoutParams.gravity = Gravity.CENTER_HORIZONTAL;
        logoAndCardImageView.setLayoutParams(layoutParams);
    }

    /**
     * This will display message in toast or logcat or on screen or all three.
     *
     * @param str           String to be logged or displayed
     * @param operationType 't' for Toast; 'n' for Logcat and Display in UI; 'd' for Toast, Logcat
     *                      and
     *                      Display in UI.
     */
    private void showMessage(final String str, final char operationType) {
        switch (operationType) {
            case TOAST:
                Toast.makeText(MainActivity.this, str, Toast.LENGTH_SHORT)
                        .show();
                break;
            case PRINT:
                information_textView.setText(str);
                information_textView.setGravity(Gravity.START);
                NxpLogUtils.i(TAG, getString(R.string.Dump_data) + str);
                break;
            case TOAST_PRINT:
                Toast.makeText(MainActivity.this, "\n" + str, Toast.LENGTH_SHORT).show();
                information_textView.setText(str);
                information_textView.setGravity(Gravity.START);
                NxpLogUtils.i(TAG, "\n" + str);
                break;
            default:
                break;
        }
    }

    private String getApplicationVersion() {
        try {
            PackageInfo pInfo = getPackageManager().getPackageInfo(getPackageName(), 0);
            return pInfo.versionName;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions,
                                           @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == STORAGE_PERMISSION_WRITE  && Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            if (grantResults.length > 0
                    && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                Toast.makeText(MainActivity.this,
                        getString(R.string.Requested_permisiion_granted),
                        Toast.LENGTH_LONG).show();
            } else {
                Toast.makeText(MainActivity.this,
                        getString(R.string.App_permission_not_granted_message),
                        Toast.LENGTH_LONG).show();
            }
        }
    }
}
