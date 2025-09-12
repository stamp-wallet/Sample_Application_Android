/*
 * *****************************************************************************************************************************
 * Copyright 2019-2025 NXP.
 * NXP Confidential. This software is owned or controlled by NXP and may only be used strictly in accordance with the applicable license terms.
 * By expressly accepting such terms or by downloading, installing, activating and/or otherwise using the software, you are agreeing that you have read, and that you agree to comply with and are bound by, such license terms.
 * If you do not agree to be bound by the applicable license terms, then you may not retain, install, activate or otherwise use the software.
 * ********************************************************************************************************************************
 *
 */


package com.nxp.sampletaplinx;

import android.app.Activity;
import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.MifareClassic;
import android.os.Bundle;
import android.os.Environment;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import com.nxp.mifaresdksample.R;

import com.nxp.nfclib.CardType;
import com.nxp.nfclib.CustomModules;
import com.nxp.nfclib.KeyType;
import com.nxp.nfclib.NxpNfcLib;
import com.nxp.nfclib.classic.ClassicFactory;
import com.nxp.nfclib.classic.IMFClassic;
import com.nxp.nfclib.classic.IMFClassicEV1;
import com.nxp.nfclib.defaultimpl.KeyData;
import com.nxp.nfclib.desfire.DESFireFactory;
import com.nxp.nfclib.desfire.DESFireFile;
import com.nxp.nfclib.desfire.EV1ApplicationKeySettings;
import com.nxp.nfclib.desfire.EV3ApplicationKeySettings;
import com.nxp.nfclib.desfire.GeneralAuthResponse;
import com.nxp.nfclib.desfire.IDESFireEV1;
import com.nxp.nfclib.desfire.IDESFireEV2;
import com.nxp.nfclib.desfire.IDESFireLight;
import com.nxp.nfclib.desfire.IMifareDUOX;
import com.nxp.nfclib.desfire.INTAG424DNA;
import com.nxp.nfclib.desfire.INTAG424DNATT;
import com.nxp.nfclib.desfire.INTag413DNA;
import com.nxp.nfclib.desfire.MifareDUOXFile;
import com.nxp.nfclib.desfire.NTAG424DNAFileSettings;
import com.nxp.nfclib.desfire.PICCFrameSize;
import com.nxp.nfclib.exceptions.NxpNfcLibException;
import com.nxp.nfclib.icode.ICode;
import com.nxp.nfclib.icode.ICodeFactory;
import com.nxp.nfclib.icode.IICodeDNA;
import com.nxp.nfclib.icode.IICodeSLI;
import com.nxp.nfclib.icode.IICodeSLIL;
import com.nxp.nfclib.icode.IICodeSLIS;
import com.nxp.nfclib.icode.IICodeSLIX;
import com.nxp.nfclib.icode.IICodeSLIX2;
import com.nxp.nfclib.icode.IICodeSLIXL;
import com.nxp.nfclib.icode.IICodeSLIXS;
import com.nxp.nfclib.interfaces.IKeyData;
import com.nxp.nfclib.ndef.NdefMessageWrapper;
import com.nxp.nfclib.ndef.NdefRecordWrapper;
import com.nxp.nfclib.ntag.INTag;
import com.nxp.nfclib.ntag.INTag213TagTamper;
import com.nxp.nfclib.ntag.NTagFactory;
import com.nxp.nfclib.plus.IPlusEV1SL0;
import com.nxp.nfclib.plus.IPlusEV1SL1;
import com.nxp.nfclib.plus.IPlusEV1SL3;
import com.nxp.nfclib.plus.IPlusSL1;
import com.nxp.nfclib.plus.IPlusSL3;
import com.nxp.nfclib.plus.PlusFactory;
import com.nxp.nfclib.plus.PlusSL1Factory;
import com.nxp.nfclib.plus.ValueBlockInfo;
import com.nxp.nfclib.ultralight.IUltralight;
import com.nxp.nfclib.ultralight.IUltralightAES;
import com.nxp.nfclib.ultralight.IUltralightC;
import com.nxp.nfclib.ultralight.IUltralightEV1;
import com.nxp.nfclib.ultralight.UltralightFactory;
import com.nxp.nfclib.ultralight.UltralightNano;
import com.nxp.nfclib.utils.NxpLogUtils;
import com.nxp.nfclib.utils.Utilities;

import java.io.File;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

//added byt stmp wallet
import com.nxp.nfclib.desfire.MFPCard.CommunicationMode;

/**
 * This class is used to write the content to the tag.
 */

public class WriteActivity extends Activity {
    /**
     * String Constants
     */
    private static final String TAG = "SampleTapLinx";
    private static final String ALIAS_KEY_AES128 = "key_aes_128";
    private static final String ALIAS_KEY_2KTDES = "key_2ktdes";
    private static final String ALIAS_KEY_2KTDES_ULC = "key_2ktdes_ulc";
    private static final String ALIAS_DEFAULT_FF = "alias_default_ff";
    private static final String ALIAS_KEY_AES128_ZEROES = "alias_default_00";
    private static final String EXTRA_KEYS_STORED_FLAG = "keys_stored_flag";
    /**
     * KEY_APP_MASTER key used for encrypting the data.
     */
    private static final String KEY_APP_MASTER = "This is my key  ";

    private static final String DATA = "This is the data";
    /**
     * Classic sector number set to 6.
     */
    private static final int DEFAULT_SECTOR_CLASSIC = 6;
    /**
     * Ultralight First User Memory Page Number.
     */
    private static final int PAGE_TO_READ_WRITE = 4;

    private static final int BLOCK_TO_READ = 6;

    private static final byte DEFAULT_ICode_PAGE = (byte) 0x10;

    private static final int PLUS_BLOCK_NO = 12;
    /**
     * Constant for permission
     */
    private static final String UNABLE_TO_WRITE = "Unable to write";
    private static final char TOAST_PRINT = 'd';
    private static final char TOAST = 't';
    private static final char PRINT = 'n';
    private static final String EMPTY_SPACE = " ";
    private static final String US_ASCII = "US-ASCII";
    private static final String UTF_8 = "UTF-8";
    /**
     * NDEF MESSAGE DATA !!
     */
    private static final String ndefData = "TapLinx";

    static String ndefDataslix2 =
            "MifareSDKTeamMifareSDKTeamMifareSDKTeamMifareSDKTeamMifareSDKTeamMifareSDKTeam" +
                    "MifareSDKTeamMifareSDKTeamMifareSDKTeamMifareSDKTeamMifareSDKTeamMifar";
    /**
     * Package Key.
     */
    private static final String packageKey = "secretkey";
    /**
     * byte array.
     */
    private byte[] data;

    private IKeyData objKEY_2KTDES = null;
    private IKeyData objKEY_AES128 = null;
    /**
     * NxpNfclib instance.
     */
    private NxpNfcLib libInstance = null;
    /**
     * bytes key.
     */
    private byte[] bytesKey = null;
    /**
     * Cipher instance.
     */
    private Cipher cipher = null;
    /**
     * Iv.
     */
    private IvParameterSpec iv = null;

    private static final byte[] APP_ID = new byte[]{0x12, 0x00, 0x00};
    private static final byte[] DATA_BYTES =
            new byte[]{(byte) 0x42, (byte) 0x43, (byte) 0x44, (byte) 0x45};

    private final StringBuilder mStringBuilder = new StringBuilder();

    private ImageView tapTagImageView;
    private TextView information_textView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.write_screen);

        libInstance = NxpNfcLib.getInstance();
        try {
            libInstance.registerActivity(this, packageKey);
        } catch (NxpNfcLibException ex) {
            Toast.makeText(this, ex.getMessage(), Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            // do nothing added to handle the crash if any
        }

        initializeView();

        initializeKeys();

        /* Initialize the Cipher and init vector of 16 bytes with 0xCD */
        initializeCipherinitVector();
    }

    private void initializeView() {
        /* Get Information text view and ImageView handle to be used further */
        information_textView = findViewById(R.id.text_info);
        information_textView.setMovementMethod(new ScrollingMovementMethod());
        Typeface face = Typeface.SANS_SERIF;
        information_textView.setTypeface(face);
        information_textView.setTextColor(Color.BLACK);

        tapTagImageView = findViewById(R.id.tap_tag_image);
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
            IKeyData objKEY_2KTDES_ULC = infoProvider.getKey(ALIAS_KEY_2KTDES_ULC,
                    SampleAppKeys.EnumKeyType.EnumDESKey);
            objKEY_2KTDES = infoProvider.getKey(ALIAS_KEY_2KTDES,
                    SampleAppKeys.EnumKeyType.EnumDESKey);
            objKEY_AES128 = infoProvider.getKey(ALIAS_KEY_AES128,
                    SampleAppKeys.EnumKeyType.EnumAESKey);
            IKeyData default_zeroes_key = infoProvider.getKey(ALIAS_KEY_AES128_ZEROES,
                    SampleAppKeys.EnumKeyType.EnumAESKey);
            byte[] default_ff_key = infoProvider.getMifareKey(ALIAS_DEFAULT_FF);
        } catch (Exception e) {
            ((ActivityManager) Objects.requireNonNull(
                    WriteActivity.this.getSystemService(ACTIVITY_SERVICE)))
                    .clearApplicationUserData();
        }
    }

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

    @Override
    public void onNewIntent(final Intent intent) {
        mStringBuilder.delete(0, mStringBuilder.length());
        writeLogic(intent);
        super.onNewIntent(intent);
        tapTagImageView.setVisibility(View.GONE);
    }

    private void writeLogic(final Intent intent) {
        CardType type = CardType.UnknownCard;
        try {
            type = libInstance.getCardType(intent);
            if (type == CardType.UnknownCard) {
                showMessage(getString(R.string.UNKNOWN_TAG), PRINT);
                information_textView.setGravity(Gravity.CENTER);
            }
        } catch (NxpNfcLibException ex) {
            showMessage(ex.getMessage(), TOAST);
        }
        switch (type) {
            case MIFAREClassic: {
                if (intent.hasExtra(NfcAdapter.EXTRA_TAG)) {
                    Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
                    if (tag != null) {
                        classicCardLogic(ClassicFactory.getInstance().getClassic(
                                MifareClassic.get(tag)));
                    }
                }
                break;
            }
            case MIFAREClassicEV1: {
                if (intent.hasExtra(NfcAdapter.EXTRA_TAG)) {
                    Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
                    if (tag != null) {
                        classicCardEV1Logic(ClassicFactory.getInstance().getClassicEV1(
                                MifareClassic.get(tag)));
                    }
                }
                break;
            }
            case Ultralight:
                try {
                    ultralightCardLogic(UltralightFactory.getInstance().getUltralight(
                            libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case UltralightEV1_11:
            case UltralightEV1_21:
                try {
                    ultralightEV1CardLogic(UltralightFactory.getInstance().getUltralightEV1(
                            libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case UltralightC:
                try {
                    ultralightcCardLogic(UltralightFactory.getInstance().getUltralightC(
                            libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTag203X:
                try {
                    ntagCardLogic(
                            NTagFactory.getInstance().getNTAG203x(libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTag210:
                try {
                    ntagCardLogic(
                            NTagFactory.getInstance().getNTAG210(libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTag213:
                try {
                    ntagCardLogic(
                            NTagFactory.getInstance().getNTAG213(libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTag215:
                try {
                    ntagCardLogic(
                            NTagFactory.getInstance().getNTAG215(libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTag216:
                try {
                    ntagCardLogic(
                            NTagFactory.getInstance().getNTAG216(libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTag213F:
                try {
                    ntagCardLogic(
                            NTagFactory.getInstance().getNTAG213F(libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTag216F:
                try {
                    ntagCardLogic(
                            NTagFactory.getInstance().getNTAG216F(libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTAG223DNA:
                try {
                    ntagCardLogic(NTagFactory.getInstance().getNTAG223DNA(libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTAG223DNAStatusDetect:
                try {
                    ntagCardLogic(NTagFactory.getInstance().getNTAG223DNAStatusDetect(libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTAG224DNA:
                try {
                    ntagCardLogic(NTagFactory.getInstance().getNTAG224DNA(libInstance.getCustomModules()));
                } catch (Throwable t) {
                    Log.e(TAG, t.getMessage());
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTAG224DNAStatusDetect:
                try {
                    ntagCardLogic(NTagFactory.getInstance().getNTAG224DNAStatusDetect(libInstance.getCustomModules()));
                } catch (Throwable t) {
                    Log.e(TAG, t.getMessage());
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case MIFAREUltralightAES:
                try {
                    ultralightAESCardLogic(UltralightFactory.getInstance().getUltralightAES(libInstance.getCustomModules()));
                } catch (Throwable t) {
                    Log.e(TAG, t.getMessage());
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTagI2C1K:
                try {
                    ntagCardLogic(
                            NTagFactory.getInstance().getNTAGI2C1K(libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTagI2C2K:
                try {
                    ntagCardLogic(
                            NTagFactory.getInstance().getNTAGI2C2K(libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTagI2CPlus1K:
                try {
                    ntagCardLogic(NTagFactory.getInstance().getNTAGI2CPlus1K(
                            libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTagI2CPlus2K:
                try {
                    ntagCardLogic(NTagFactory.getInstance().getNTAGI2CPlus2K(
                            libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTag210u:
                try {
                    ntagCardLogic(
                            NTagFactory.getInstance().getNTAG210u(libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTag413DNA:
                try {
                    ntag413CardLogic(DESFireFactory.getInstance().getNTag413DNA(
                            libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;

            case NTAG424DNA:
                try {
                    tag424DNACardLogic(DESFireFactory.getInstance().getNTAG424DNA(
                            libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTAG424DNATagTamper:
                try {
                    tag424DNATTCardLogic(DESFireFactory.getInstance().getNTAG424DNATT(
                            libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case NTag213TagTamper:
                try {
                    ntag213TTCardLogic(NTagFactory.getInstance().getNTAG213TagTamper(
                            libInstance.getCustomModules()));
                } catch (Throwable t) {
                    t.printStackTrace();
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case ICodeSLI:
                try {
                    iCodeSLICardLogic(
                            ICodeFactory.getInstance().getICodeSLI(libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case ICodeSLIS:
                try {
                    iCodeSLISCardLogic(ICodeFactory.getInstance().getICodeSLIS(
                            libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case ICodeSLIL:
                try {
                    iCodeSLILCardLogic(ICodeFactory.getInstance().getICodeSLIL(
                            libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case ICodeSLIX:
                try {
                    iCodeSLIXCardLogic(ICodeFactory.getInstance().getICodeSLIX(
                            libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case ICodeSLIXS:
                try {
                    iCodeSLIXSCardLogic(ICodeFactory.getInstance().getICodeSLIXS(
                            libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case ICodeSLIXL:
                try {
                    iCodeSLIXLCardLogic(ICodeFactory.getInstance().getICodeSLIXL(
                            libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case ICodeSLIX2:
                try {
                    iCodeSLIX2CardLogic(ICodeFactory.getInstance().getICodeSLIX2(
                            libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case ICodeDNA:
                try {
                    iCodeDNACardLogic(
                            ICodeFactory.getInstance().getICodeDNA(libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
//            case NTAG5:
//                try {
//                    iNTagFiveCardLogic(
//                            ICodeFactory.getInstance().getNTAG5(libInstance.getCustomModules()));
//                } catch (Throwable t) {
//                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
//                }
//                break;
            case DESFireEV1:
                try {
                    desfireEV1CardLogic(DESFireFactory.getInstance().getDESFire(
                            libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case DESFireEV2:
                IDESFireEV2 desFireEV2 = DESFireFactory.getInstance().getDESFireEV2(
                        libInstance.getCustomModules());
                try {
                    desFireEV2.getReader().connect();
                    desfireEV2CardLogic(desFireEV2);
                } catch (Throwable t) {
                    t.printStackTrace();
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case DESFireLight:
                IDESFireLight idesFireLight = DESFireFactory.getInstance().getDESFireLight(
                        libInstance.getCustomModules());
                try {
                    idesFireLight.getReader().connect();
                    desfireLightCardLogic(idesFireLight);
                } catch (Throwable t) {
                    t.printStackTrace();
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case PlusSL0:
                showMessage(getString(R.string.No_Operations_executed_on_Plus_SL0), TOAST_PRINT);
                break;
            case PlusSL1:
                Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
                MifareClassic obj = MifareClassic.get(tag);
                IPlusSL1 plusSL1;
                if (obj != null) {
                    plusSL1 = PlusSL1Factory.getInstance().getPlusSL1(
                            libInstance.getCustomModules(), obj);
                    plusSL1CardLogic(plusSL1);
                } else {
                    plusSL1 = PlusSL1Factory.getInstance().getPlusSL1(
                            libInstance.getCustomModules());
                    showMessage(getString(R.string.Plus_SL1_Operations_not_supported_on_device),
                            TOAST_PRINT);
                    //sample code to switch sector to security level 3. commented because changes
                    // are irreversible.
                    //plusSL1.switchToSL3(objKEY_AES128);
                }
                break;
            case PlusSL3:
                IPlusSL3 plusSL3 = PlusFactory.getInstance().getPlusSL3(
                        libInstance.getCustomModules());
                try {
                    plusSL3.getReader().connect();
                    plusSL3CardLogic(plusSL3);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case PlusEV1SL0:
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
                tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
                obj = MifareClassic.get(tag);
                IPlusEV1SL1 plusEV1SL1;
                if (obj != null) {
                    plusEV1SL1 = PlusSL1Factory.getInstance().getPlusEV1SL1(
                            libInstance.getCustomModules());
                    plusEV1SL1CardLogic(plusEV1SL1);
                } else {
                    plusEV1SL1 = PlusSL1Factory.getInstance().getPlusEV1SL1(
                            libInstance.getCustomModules());
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
                    plusEV1SL3CardLogic(plusEV1SL3);
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case UltralightNano_40:
                showMessage(getString(R.string.Card_Detected) + getString(R.string.UL_nano_40),
                        TOAST);
                try {
                    ultralightNanoCardLogic(UltralightFactory.getInstance().getUltralightNano(
                            libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;

            case UltralightNano_48:
                showMessage(getString(R.string.Card_Detected) + getString(R.string.UL_nano_48),
                        TOAST);
                try {
                    ultralightNanoCardLogic(UltralightFactory.getInstance().getUltralightNano(
                            libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
            case MifareDUOX:
                try {
                    mifareDUOXCardLogic(DESFireFactory.getInstance().getMifareDUOX(
                            libInstance.getCustomModules()));
                } catch (Throwable t) {
                    showMessage(getString(R.string.unknown_Error_Tap_Again), TOAST_PRINT);
                }
                break;
        }
    }


    /**
     * MIFARE Plus Pre-condition.
     * <p/>
     * - PICC should be SL3. AuthenticateSL3 API requires block number to be
     * authenticated with AES128 key. Default key -
     * 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, KeyNo - specify(0-9) during
     * set/getkey, KeyVersion - specify(0-2) Diversification input is null,
     * pcdCap2Out/pdCap2/pcdCap2In is a byte array.
     * <p/>
     * <p/>
     * ReadValue API require parameters(byte encrypted, byte readMACed, byte
     * macOnCmd, int blockNo, byte dstBlock).Result will print read data from
     * corresponding block(4 bytes).
     */
    private void plusSL3CardLogic(IPlusSL3 plusSL3) {
        ValueBlockInfo valueResult;
        byte[] dataWrite = new byte[]{(byte) 0x16, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0xE9, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0x16, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x04, (byte) 0xFB, (byte) 0x04,
                (byte) 0xFB, (byte) 0x21, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0xDE, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0x21, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x05, (byte) 0xFA, (byte) 0x05,
                (byte) 0xFA, (byte) 0x2C, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0xD3, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0x2C, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x06, (byte) 0xF9, (byte) 0x06, (byte) 0x00};
        mStringBuilder.append(getString(R.string.Card_Detected)).append(
                plusSL3.getType().getTagName());
        mStringBuilder.append("\n\n");
        mStringBuilder.append(getString(R.string.Sub_Type)).append(plusSL3.getPlusType());
        mStringBuilder.append("\n\n");
        if (plusSL3.getCardDetails().securityLevel.equals(getString(R.string.SL3))) {
            try {
                /* Write Plain, MAC on response, MAC on command. This works on all variants
                  of Plus - S, SE and X*/
                mStringBuilder.append(getString(R.string.Writing_to_tag_at_block_no)).append(
                        PLUS_BLOCK_NO);
                mStringBuilder.append("\n\n");
                plusSL3.writeValue(IPlusSL3.WriteMode.Plain_ResponseMACed, PLUS_BLOCK_NO, 999,
                        (byte) 0x09);
                mStringBuilder.append(getString(R.string.Writing_to_tag_at_block_no)).append(
                        PLUS_BLOCK_NO).append(" is successful.");
                mStringBuilder.append("\n\n");
                /* Read plain,  MAC on response, MAC on command. This works on all variants
                 * of Plus - S, SE and X*/
                valueResult = plusSL3.readValue(
                        IPlusSL3.ReadMode.Plain_ResponseMACed_CommandMACed, PLUS_BLOCK_NO);
                mStringBuilder.append(getString(R.string.Read_value_from_block)).append(
                        PLUS_BLOCK_NO).append(": ").append(valueResult.getDataValue());
                mStringBuilder.append("\n\n");
                mStringBuilder.append(getString(R.string.Writing_multiple_blocks)).append(
                        PLUS_BLOCK_NO);
                mStringBuilder.append("\n\n");
                plusSL3.multiBlockWrite(IPlusSL3.WriteMode.Plain_ResponseMACed,
                        (byte) PLUS_BLOCK_NO, 3,
                        dataWrite);
                mStringBuilder.append(getString(R.string.Multiblock_write_True));
                mStringBuilder.append("\n\n");
                showMessage(mStringBuilder.toString(), PRINT);
                //To save the logs to file \sdcard\NxpLogDump\logdump.xml
                NxpLogUtils.save();
            } catch (Exception e) {
                writeFailedMessage();
                mStringBuilder.append(e.getMessage());
                showMessage(mStringBuilder.toString(), PRINT);
                NxpLogUtils.save();
            }
        } else {
            mStringBuilder.append(getString(R.string.No_operation_done_since_card_in_SL0));
            mStringBuilder.append("\n\n");
            showMessage(mStringBuilder.toString(), PRINT);
        }
    }

    private void plusEV1SL3CardLogic(IPlusEV1SL3 plusEV1SL3) {
        ValueBlockInfo valueResult;
        byte[] dataWrite = new byte[]{(byte) 0x16, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0xE9, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0x16, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x04, (byte) 0xFB, (byte) 0x04,
                (byte) 0xFB, (byte) 0x21, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0xDE, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0x21, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x05, (byte) 0xFA, (byte) 0x05,
                (byte) 0xFA, (byte) 0x2C, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0xD3, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0x2C, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x06, (byte) 0xF9, (byte) 0x06, (byte) 0x00};
        byte[] pcdCap2In = new byte[]{0x01};
        mStringBuilder.append(getString(R.string.Card_Detected)).append(
                plusEV1SL3.getType().getTagName());
        mStringBuilder.append("\n\n");
        try {
            /* Write Plain, MAC on response, MAC on command. This works on all variants of
             * Plus - S, SE and X*/
            mStringBuilder.append(getString(R.string.Writing_to_tag_at_block_no)).append(
                    PLUS_BLOCK_NO);
            mStringBuilder.append("\n\n");
            plusEV1SL3.authenticateFirst(0x4006, objKEY_AES128, pcdCap2In);
            plusEV1SL3.writeValue(IPlusSL3.WriteMode.Plain_ResponseMACed, PLUS_BLOCK_NO, 999,
                    (byte) 0x09);
            mStringBuilder.append(getString(R.string.Writing_to_tag_at_block_no)).append(
                    PLUS_BLOCK_NO).append(" is successful.");
            mStringBuilder.append("\n\n");
            /* Write Plain, MAC on response, MAC on command. This works on all variants of
             * Plus - S, SE and X*/
            valueResult = plusEV1SL3.readValue(
                    IPlusSL3.ReadMode.Plain_ResponseMACed_CommandMACed, PLUS_BLOCK_NO);
            mStringBuilder.append(getString(R.string.Read_value_from_block)).append(
                    PLUS_BLOCK_NO).append(": ").append(valueResult.getDataValue());
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Writing_multiple_blocks)).append(
                    PLUS_BLOCK_NO);
            mStringBuilder.append("\n\n");
            plusEV1SL3.multiBlockWrite(IPlusSL3.WriteMode.Plain_ResponseMACed, (byte) 12, 3,
                    dataWrite);
            mStringBuilder.append(getString(R.string.Multiblock_write_True));
            mStringBuilder.append("\n\n");
            showMessage(mStringBuilder.toString(), PRINT);
            //To save the logs to file \sdcard\NxpLogDump\logdump.xml
            NxpLogUtils.save();
        } catch (Exception e) {
            writeFailedMessage();
            mStringBuilder.append(e.getMessage());
            showMessage(mStringBuilder.toString(), PRINT);
            NxpLogUtils.save();
        }
    }

    /**
     * MIFARE Plus SL1 Card Logic.
     */
    private void plusSL1CardLogic(IPlusSL1 plusSL1) {
        int blockTorw = DEFAULT_SECTOR_CLASSIC;
        mStringBuilder.append(getString(R.string.Card_Detected)).append(
                plusSL1.getType().getTagName());
        try {
            /* write data to tag */
            mStringBuilder.append(getString(R.string.Writing_to_tag_at_block_no)).append(blockTorw);
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_to_write)).append(DATA);
            plusSL1.writeBlock(blockTorw, DATA.getBytes());
            mStringBuilder.append(getString(R.string.Writing_to_tag_at_block_no)).append(
                    blockTorw).append(" is successful.");
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Reading_tag_at_block_number)).append(
                    blockTorw);
            mStringBuilder.append("\n\n");
            mStringBuilder.append("Data read from tag: ").append(
                    Utilities.dumpBytes(plusSL1.readBlock(blockTorw)));
            mStringBuilder.append("\n\n");
            showMessage(mStringBuilder.toString(), PRINT);
            //To save the logs to file \sdcard\NxpLogDump\logdump.xml
            NxpLogUtils.save();
        } catch (Exception e) {
            writeFailedMessage();
            mStringBuilder.append(e.getMessage());
            showMessage(mStringBuilder.toString(), PRINT);
            NxpLogUtils.save();
        }
    }

    private void plusEV1SL1CardLogic(IPlusEV1SL1 plusEV1SL1) {
        try {
            mStringBuilder.append(getString(R.string.Card_Detected)).append(
                    plusEV1SL1.getType().getTagName());
            if (!plusEV1SL1.getReader().isConnected()) {
                plusEV1SL1.getReader().connect();
            }
            mStringBuilder.append(getString(R.string.Writing_to_tag_at_block_no)).append(
                    BLOCK_TO_READ);
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_to_write)).append(DATA);
            plusEV1SL1.writeBlock(BLOCK_TO_READ, DATA.getBytes());
            mStringBuilder.append(getString(R.string.Writing_to_tag_at_block_no)).append(
                    BLOCK_TO_READ).append(" is successful.");
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Reading_tag_at_block_number)).append(
                    BLOCK_TO_READ);
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_read_from_the_card)).append(
                    Utilities.dumpBytes(
                            plusEV1SL1.readBlock(BLOCK_TO_READ)));
            mStringBuilder.append("\n\n");
            showMessage(mStringBuilder.toString(), PRINT);
            //To save the logs to file \sdcard\NxpLogDump\logdump.xml
            NxpLogUtils.save();
        } catch (Exception e) {
            writeFailedMessage();
            mStringBuilder.append(e.getMessage());
            showMessage(mStringBuilder.toString(), PRINT);
            NxpLogUtils.save();
        }
    }

    /**
     * MIFARE Ultralight EV1 CardLogic.
     */
    private void ultralightEV1CardLogic(IUltralightEV1 ultralightEV1) {
        ultralightEV1.getReader().connect();
        mStringBuilder.append(getString(R.string.Card_Detected)).append(
                ultralightEV1.getType().getTagName());
        mStringBuilder.append("\n\n");
        try {
            data = ultralightEV1.read(PAGE_TO_READ_WRITE);
            String str = Utilities.dumpBytes(data);
            mStringBuilder.append(getString(R.string.Data_read_from_page)).append(
                    PAGE_TO_READ_WRITE).append(" is : ").append(str);
            mStringBuilder.append("\n\n");
            byte[] bytesData = DATA.getBytes();
            String s1 = new String(bytesData);
            mStringBuilder.append(getString(R.string.Input_string_is)).append(s1);
            mStringBuilder.append("\n\n");
            byte[] bytesEncData = encryptAESData(bytesData, bytesKey);
            str = getString(R.string.Encrypted_string_is) + Utilities.dumpBytes(bytesEncData);
            mStringBuilder.append(str);
            mStringBuilder.append("\n\n");

            ultralightEV1.write(4, Arrays.copyOfRange(bytesEncData, 0, 4));
            ultralightEV1.write(5, Arrays.copyOfRange(bytesEncData, 4, 8));
            ultralightEV1.write(6, Arrays.copyOfRange(bytesEncData, 8, 12));
            ultralightEV1.write(7, Arrays.copyOfRange(bytesEncData, 12, 16));

            byte[] bytesDecData = decryptAESData(data, bytesKey);
            String s = new String(bytesDecData);
            str = getString(R.string.Decrypted_string_is) + s;
            mStringBuilder.append(str);
            mStringBuilder.append("\n\n");
            showMessage(mStringBuilder.toString(), PRINT);
            //To save the logs to file \sdcard\NxpLogDump\logdump.xml
            NxpLogUtils.save();
        } catch (Exception e) {
            writeFailedMessage();
            mStringBuilder.append(e.getMessage());
            showMessage(mStringBuilder.toString(), PRINT);
            NxpLogUtils.save();
        }
    }

    /**
     * MIFARE Ultralight-C Card Logic.
     */
    private void ultralightcCardLogic(IUltralightC ultralightC) {
        ultralightC.getReader().connect();
        mStringBuilder.append(getString(R.string.Card_Detected)).append(
                ultralightC.getType().getTagName());
        mStringBuilder.append("\n\n");
        byte[] data = new byte[]{(byte) 0x42, (byte) 0x43, (byte) 0x44, (byte) 0x45};
        try {
            mStringBuilder.append(getString(R.string.Writing_data_at_page_number)).append(
                    PAGE_TO_READ_WRITE).append("...");
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_to_write)).append(
                    Utilities.dumpBytes(data));
            mStringBuilder.append("\n\n");
            ultralightC.write(PAGE_TO_READ_WRITE, data);
            mStringBuilder.append(getString(R.string.Data_written_successfully));
            mStringBuilder.append("\n\n");
            byte[] dataRead = ultralightC.read(4);
            mStringBuilder.append(getString(R.string.Data_read_from_page)).append(
                    PAGE_TO_READ_WRITE).append(": ").append(
                    Utilities.dumpBytes(Arrays.copyOfRange(dataRead, 0, 4)));
            mStringBuilder.append("\n\n");
            showMessage(mStringBuilder.toString(), PRINT);
            //To save the logs to file \sdcard\NxpLogDump\logdump.xml
            NxpLogUtils.save();
        } catch (Exception e) {
            writeFailedMessage();
            mStringBuilder.append(e.getMessage());
            showMessage(mStringBuilder.toString(), PRINT);
            NxpLogUtils.save();
        }
    }

    /**
     * Ultralight Card Logic.
     */
    private void ultralightCardLogic(IUltralight ultralightBase) {
        ultralightBase.getReader().connect();
        mStringBuilder.append(getString(R.string.Card_Detected)).append(
                ultralightBase.getType().getTagName());
        mStringBuilder.append("\n\n");
        byte[] data = new byte[]{(byte) 0x42, (byte) 0x43, (byte) 0x44, (byte) 0x45};
        try {
            mStringBuilder.append(getString(R.string.Writing_data_at_page_number)).append(
                    PAGE_TO_READ_WRITE).append("...");
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_to_write)).append(
                    Utilities.dumpBytes(data));
            mStringBuilder.append("\n\n");
            ultralightBase.write(PAGE_TO_READ_WRITE, data);
            mStringBuilder.append(getString(R.string.Data_written_successfully));
            mStringBuilder.append("\n\n");
            byte[] dataRead = ultralightBase.read(PAGE_TO_READ_WRITE);
            mStringBuilder.append(getString(R.string.Data_read_from_page)).append(
                    PAGE_TO_READ_WRITE).append(": ").append(
                    Utilities.dumpBytes(Arrays.copyOfRange(dataRead, 0, 4)));
            mStringBuilder.append("\n\n");
            showMessage(mStringBuilder.toString(), PRINT);
            //To save the logs to file \sdcard\NxpLogDump\logdump.xml
            NxpLogUtils.save();
        } catch (Exception e) {
            writeFailedMessage();
            mStringBuilder.append(e.getMessage());
            showMessage(mStringBuilder.toString(), PRINT);
            NxpLogUtils.save();
        }
    }

    private void ultralightNanoCardLogic(UltralightNano ultralightNano) {
        if (!ultralightNano.getReader().isConnected()) {
            ultralightNano.getReader().connect();
        }
        mStringBuilder.append(getString(R.string.Card_Detected)).append(
                ultralightNano.getType().getTagName());
        mStringBuilder.append("\n\n");
        byte[] data = new byte[]{(byte) 0x42, (byte) 0x43, (byte) 0x44,
                (byte) 0x45};
        try {
            mStringBuilder.append(getString(R.string.Writing_data_at_page_number)).append(
                    PAGE_TO_READ_WRITE).append("...");
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_to_write)).append(
                    Utilities.dumpBytes(data));
            mStringBuilder.append("\n\n");
            ultralightNano.write(PAGE_TO_READ_WRITE, data);
            mStringBuilder.append(getString(R.string.Data_written_successfully));
            mStringBuilder.append("\n\n");
            byte[] dataRead = ultralightNano.read(PAGE_TO_READ_WRITE);
            mStringBuilder.append(getString(R.string.Data_read_from_page)).append(
                    PAGE_TO_READ_WRITE).append(": ").append(
                    Utilities.dumpBytes(Arrays.copyOfRange(dataRead, 0, 4)));
            mStringBuilder.append("\n\n");
            showMessage(mStringBuilder.toString(), PRINT);
            //To save the logs to file \sdcard\NxpLogDump\logdump.xml
            NxpLogUtils.save();
        } catch (Exception e) {
            writeFailedMessage();
            mStringBuilder.append(e.getMessage());
            showMessage(mStringBuilder.toString(), PRINT);
            NxpLogUtils.save();
        }
    }

    /**
     * MIFARE classic Card Logic.
     */
    private void classicCardLogic(IMFClassic mifareClassic) {
        int blockTorw = DEFAULT_SECTOR_CLASSIC;
        mStringBuilder.append(getString(R.string.Card_Detected)).append(
                mifareClassic.getType().getTagName());
        mStringBuilder.append("\n\n");
        try {
            /* write data to tag */
            mStringBuilder.append(getString(R.string.Writing_to_tag_at_block_no)).append(
                    blockTorw).append("...");
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_to_write)).append(DATA);
            mStringBuilder.append("\n\n");
            mifareClassic.writeBlock(blockTorw, DATA.getBytes());
            mStringBuilder.append(getString(R.string.Data_written_successfully));
            mStringBuilder.append("\n\n");
            showMessage(mStringBuilder.toString(), PRINT);
            //To save the logs to file \sdcard\NxpLogDump\logdump.xml
            NxpLogUtils.save();
        } catch (Exception e) {
            writeFailedMessage();
            mStringBuilder.append(e.getMessage());
            showMessage(mStringBuilder.toString(), PRINT);
            NxpLogUtils.save();
        }
    }

    /**
     * MIFARE classic EV1 Card Logic.
     */
    private void classicCardEV1Logic(IMFClassicEV1 mifareClassicEv1) {
        int blockTorw = DEFAULT_SECTOR_CLASSIC;
        try {
            /* write data to tag */
            mStringBuilder.append(getString(R.string.Writing_to_tag_at_block_no)).append(
                    blockTorw).append("...");
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_to_write)).append(DATA);
            mStringBuilder.append("\n\n");
            mifareClassicEv1.writeBlock(blockTorw, DATA.getBytes());
            mStringBuilder.append(getString(R.string.Data_written_successfully));
            mStringBuilder.append("\n\n");
            showMessage(mStringBuilder.toString(), PRINT);
            //To save the logs to file \sdcard\NxpLogDump\logdump.xml
            NxpLogUtils.save();
        } catch (Exception e) {
            writeFailedMessage();
            mStringBuilder.append(e.getMessage());
            showMessage(mStringBuilder.toString(), PRINT);
            NxpLogUtils.save();
        }
    }

    /**
     * DESFire Pre Conditions.
     * <p/>
     * PICC Master key should be factory default settings, (ie 16 byte All zero
     * Key ).
     * <p/>
     */
    private void desfireEV1CardLogic(IDESFireEV1 desFireEV1) {
        desFireEV1.getReader().connect();
        desFireEV1.getReader().setTimeout(2000);
        int fileSize = 100;
        byte[] data = new byte[]{0x11, 0x11, 0x11, 0x11, 0x11};
        int fileNo = 0;
        mStringBuilder.append(getString(R.string.Card_Detected)).append(
                desFireEV1.getType().getTagName());
        mStringBuilder.append("\n\n");
        try {
            mStringBuilder.append(getString(R.string.Selecting_PICC));
            mStringBuilder.append("\n\n");
            desFireEV1.selectApplication(0);
            mStringBuilder.append(getString(R.string.PICC_selection_success));
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Auth_with_default_key));
            mStringBuilder.append("\n\n");
            desFireEV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.THREEDES,
                    objKEY_2KTDES);
            mStringBuilder.append(getString(R.string.Authentication_status_true));
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Creating_application));
            mStringBuilder.append("\n\n");
            EV1ApplicationKeySettings.Builder appsetbuilder =
                    new EV1ApplicationKeySettings.Builder();
            EV1ApplicationKeySettings appsettings = appsetbuilder.setAppKeySettingsChangeable(
                    true).setAppMasterKeyChangeable(true)
                    .setAuthenticationRequiredForFileManagement(false)
                    .setAuthenticationRequiredForDirectoryConfigurationData(
                            false).setKeyTypeOfApplicationKeys(
                            KeyType.TWO_KEY_THREEDES).build();
            desFireEV1.createApplication(APP_ID, appsettings);
            mStringBuilder.append(getString(R.string.App_creation_success)).append(
                    Utilities.dumpBytes(APP_ID));
            mStringBuilder.append("\n\n");
            desFireEV1.selectApplication(APP_ID);
            desFireEV1.createFile(fileNo, new DESFireFile.StdDataFileSettings(
                    IDESFireEV1.CommunicationType.Plain, (byte) 0, (byte) 0, (byte) 0, (byte) 0,
                    fileSize));
            desFireEV1.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.TWO_KEY_THREEDES,
                    objKEY_2KTDES);
            mStringBuilder.append(getString(R.string.Writing_data_to_tag));
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_to_write)).append(
                    Utilities.dumpBytes(data));
            mStringBuilder.append("\n\n");
            desFireEV1.writeData(0, 0, data);
            mStringBuilder.append(getString(R.string.Data_written_successfully));
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_read_from_the_card)).append(
                    Utilities.dumpBytes(desFireEV1.readData(0, 0, 5)));
            mStringBuilder.append("\n\n");
            showMessage(mStringBuilder.toString(), PRINT);
            desFireEV1.getReader().close();
            // Set the custom path where logs will get stored, here we are setting the log
            // folder DESFireLogs under external storage.
            String spath = Environment.getExternalStorageDirectory().getPath() + File.separator
                    + getString(R.string.DESFireLogs);
            NxpLogUtils.setLogFilePath(spath);
            // if you don't call save as below , logs will not be saved.
            NxpLogUtils.save();
        } catch (Exception e) {
            writeFailedMessage();
            mStringBuilder.append(e.getMessage());
            showMessage(mStringBuilder.toString(), PRINT);
            NxpLogUtils.save();
        }
    }

    private void desfireEV2CardLogic(IDESFireEV2 desFireEV2) {
        int fileSize = 100;
        byte[] data = new byte[]{0x11, 0x11, 0x11, 0x11, 0x11};
        int timeOut = 2000;
        int fileNo = 0;
        mStringBuilder.append(getString(R.string.Card_Detected)).append(
                desFireEV2.getType().getTagName());
        mStringBuilder.append("\n\n");
        try {
            mStringBuilder.append(getString(R.string.Selecting_PICC));
            mStringBuilder.append("\n\n");
            desFireEV2.selectApplication(0);
            mStringBuilder.append(getString(R.string.PICC_selection_success));
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Auth_with_default_key));
            mStringBuilder.append("\n\n");
            desFireEV2.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.THREEDES,
                    objKEY_2KTDES);
            mStringBuilder.append(getString(R.string.Authentication_status_true));
            mStringBuilder.append("\n\n");
            desFireEV2.getReader().setTimeout(timeOut);
            mStringBuilder.append(getString(R.string.Creating_application));
            mStringBuilder.append("\n\n");
            EV1ApplicationKeySettings.Builder appsetbuilder =
                    new EV1ApplicationKeySettings.Builder();
            EV1ApplicationKeySettings appsettings = appsetbuilder.setAppKeySettingsChangeable(
                    true).setAppMasterKeyChangeable(true)
                    .setAuthenticationRequiredForFileManagement(false)
                    .setAuthenticationRequiredForDirectoryConfigurationData(
                            false).setKeyTypeOfApplicationKeys(
                            KeyType.TWO_KEY_THREEDES).build();
            desFireEV2.createApplication(APP_ID, appsettings);
            mStringBuilder.append(getString(R.string.App_creation_success)).append(
                    Utilities.dumpBytes(APP_ID));
            mStringBuilder.append("\n\n");
            desFireEV2.selectApplication(APP_ID);
            desFireEV2.createFile(fileNo, new DESFireFile.StdDataFileSettings(
                    IDESFireEV1.CommunicationType.Plain, (byte) 0, (byte) 0, (byte) 0, (byte) 0,
                    fileSize));
            desFireEV2.authenticate(0, IDESFireEV1.AuthType.Native, KeyType.TWO_KEY_THREEDES,
                    objKEY_2KTDES);
            mStringBuilder.append(getString(R.string.Writing_data_to_tag));
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_to_write)).append(
                    Utilities.dumpBytes(data));
            mStringBuilder.append("\n\n");
            desFireEV2.writeData(0, 0, data);
            mStringBuilder.append(getString(R.string.Data_written_successfully));
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_read_from_the_card)).append(
                    Utilities.dumpBytes(desFireEV2.readData(0, 0, 5)));
            mStringBuilder.append("\n\n");
            showMessage(mStringBuilder.toString(), PRINT);
            desFireEV2.getReader().close();
            // Set the custom path where logs will get stored, here we are setting the log folder
            // DESFireLogs under external storage.
            String spath = Environment.getExternalStorageDirectory().getPath() + File.separator
                    + getString(R.string.DESFireLogs);
            NxpLogUtils.setLogFilePath(spath);
            // if you don't call save as below , logs will not be saved.
            NxpLogUtils.save();
        } catch (Exception e) {
            writeFailedMessage();
            mStringBuilder.append(e.getMessage());
            showMessage(mStringBuilder.toString(), PRINT);
            NxpLogUtils.save();
        }
    }

    private void desfireLightCardLogic(IDESFireLight idesFireLight) {
        byte[] appDFName =
                {(byte) 0xA0, 0x00, 0x00, 0x03, (byte) 0x96, 0x56, 0x43, 0x41, 0x03, (byte) 0xF0,
                        0x15, 0x40,
                        0x00, 0x00, 0x00, 0x0B};

        byte[] data =
                {(byte) 0xA0, 0x00, 0x00, 0x03, (byte) 0x96, 0x56, 0x43, 0x41, 0x03, (byte) 0xF0,
                        0x15, 0x40, 0x00,
                        0x00, 0x00, 0x0B, (byte) 0xA0, 0x00, 0x00, 0x03, (byte) 0x96, 0x56, 0x43,
                        0x41, 0x03, (byte) 0xF0, 0x15,
                        0x40, 0x00, 0x00, 0x00, 0x0B};
        byte[] KEY_AES128_DEFAULT =
                {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                        (byte) 0x00, (byte) 0x00, (byte) 0x00,
                        (byte) 0x00, (byte) 0x00};
        KeyData aesKeyData = new KeyData();
        byte[] PCD_CAP = {(byte) 0x00, (byte) 0x00};

        mStringBuilder.append(getString(R.string.Card_Detected)).append(
                idesFireLight.getType().getTagName());
        mStringBuilder.append("\n\n");
        int timeOut = 2000;
        try {
            idesFireLight.isoSelectApplicationByDFName(appDFName);
            Key keyDefault = new SecretKeySpec(KEY_AES128_DEFAULT, "AES");
            aesKeyData.setKey(keyDefault);
            idesFireLight.authenticateEV2First(0, aesKeyData, PCD_CAP);
            mStringBuilder.append(getString(R.string.Authentication_status_true));
            mStringBuilder.append("\n\n");
            idesFireLight.getReader().setTimeout(timeOut);
            mStringBuilder.append(getString(R.string.Writing_data_to_Default_file));
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_to_write)).append(
                    Utilities.dumpBytes(data));
            mStringBuilder.append("\n\n");
            idesFireLight.writeData(0, 0, data);
            mStringBuilder.append(getString(R.string.Data_written_successfully));
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_read_from_the_card)).append(
                    Utilities.dumpBytes(idesFireLight.readData(0, 0, data.length)));
            mStringBuilder.append("\n\n");
            showMessage(mStringBuilder.toString(), PRINT);
            idesFireLight.getReader().close();
        } catch (Exception e) {
            writeFailedMessage();
            mStringBuilder.append(e.getMessage());
            showMessage(mStringBuilder.toString(), PRINT);
            NxpLogUtils.save();
        }

    }

    private void ntag413CardLogic(final INTag413DNA tag) {
        byte[] writeDataByte =
                new byte[]{(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                        (byte) 0x06, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                        (byte) 0x05, (byte) 0x06};
        byte[] readDataByte;
        mStringBuilder.append(getString(R.string.Card_Detected)).append(tag.getType().getTagName());
        mStringBuilder.append("\n\n");
        try {
            mStringBuilder.append(getString(R.string.Writing_data_to_tag));
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_to_write)).append(
                    Utilities.dumpBytes(writeDataByte));
            mStringBuilder.append("\n\n");
            tag.writeData(2, 0, writeDataByte);
            mStringBuilder.append(getString(R.string.Data_written_successfully));
            mStringBuilder.append("\n\n");
            readDataByte = tag.readData(2, 0, writeDataByte.length);
            mStringBuilder.append(getString(R.string.Data_read_from_the_card)).append(
                    Utilities.dumpBytes(readDataByte));
            mStringBuilder.append("\n\n");
            showMessage(mStringBuilder.toString(), PRINT);
            //To save the logs to file \sdcard\NxpLogDump\logdump.xml
            NxpLogUtils.save();
        } catch (Exception e) {
            writeFailedMessage();
            mStringBuilder.append(e.getMessage());
            showMessage(mStringBuilder.toString(), PRINT);
            NxpLogUtils.save();
        }

    }

    private void tag424DNACardLogic(INTAG424DNA ntag424DNA) {
        Log.e("tag424DNACardLogic","sushil");
        byte[] KEY_AES128_DEFAULT = {
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00
        };
        byte[] NTAG424DNA_APP_NAME =
                {(byte) 0xD2, (byte) 0x76, 0x00, 0x00, (byte) 0x85, 0x01, 0x01};
        byte[] data ={ 0x73, 0x75, 0x73, 0x68, 0x69, 0x6C };

        mStringBuilder.append("\n\n");
        int timeOut = 2000;
        try {
            ntag424DNA.isoSelectApplicationByDFName(NTAG424DNA_APP_NAME);
            KeyData aesKeyData = new KeyData();
            Key keyDefault = new SecretKeySpec(KEY_AES128_DEFAULT, "AES");
            aesKeyData.setKey(keyDefault);
            ntag424DNA.authenticateEV2First(0, aesKeyData, null);
            mStringBuilder.append(getString(R.string.Authentication_status_true));
            mStringBuilder.append("\n\n");

            String jsonTemplate = "{\"configId\":\"1\",\"businessId\":\"1\",\"cmac\":\"\",\"counter\":\"\",\"uuid\":\"\"}";
            byte[] jsonBytes = jsonTemplate.getBytes("UTF-8");

            int cmacStartCharIndex = jsonTemplate.indexOf("\"cmac\":\"\"") + "\"cmac\":\"".length();
            int counterStartCharIndex = jsonTemplate.indexOf("\"counter\":\"\"") + "\"counter\":\"".length();
            int uuidStartCharIndex = jsonTemplate.indexOf("\"uuid\":\"\"") + "\"uuid\":\"".length();

            NTAG424DNAFileSettings fs = new NTAG424DNAFileSettings(
                    CommunicationMode.Plain,  // or MAC/ENC depending on your security
                    (byte) 0x02,              // file number = 0x02 (NDEF)
                    (byte) 0x02,              // read key
                    (byte) 0x0E,              // write key (0x0E = never)
                    (byte) 0x0E               // change key (0x0E = never)
            );

            ntag424DNA.changeFileSettings(0x02, fs);

            fs.setSDMEncryptFileDataEnabled(true);
            fs.setUIDMirroringEnabled(true);
            fs.setSDMReadCounterEnabled(true);
            byte[] bytes = new byte[] { (byte) 0x1A, (byte) 0x00, (byte) 0x00 };
            fs.setSdmAccessRights(bytes);

            byte[] setUidOffset = new byte[] { (byte) 0x1A, (byte) 0x00, (byte) 0x00 };
            fs.setUidOffset(setUidOffset);

            byte[] sdmReadCounterOffset = new byte[] { (byte)(counterStartCharIndex & 0xFF), 0x00, 0x00 };

            fs.setSdmReadCounterOffset(sdmReadCounterOffset);

            byte[] setSdmMacOffset =  new byte[] { (byte)(cmacStartCharIndex & 0xFF), 0x00, 0x00 };
            fs.setSdmMacOffset(setSdmMacOffset);

            byte[] sdmMacInputOffset = new byte[] { (byte)(uuidStartCharIndex & 0xFF), 0x00, 0x00 };
            fs.setSdmMacInputOffset(sdmMacInputOffset);

            byte[] type = "U".getBytes("US-ASCII");

            // Create NDEF record
            NdefRecordWrapper record = new NdefRecordWrapper(
                    NdefRecordWrapper.TNF_WELL_KNOWN,
                    type,
                    new byte[0],  // empty ID
                    jsonBytes     // payload (your JSON)
            );

            // Wrap record into NDEF message
            NdefMessageWrapper msg = new NdefMessageWrapper(record);

            ntag424DNA.writeNDEF(msg);
            Log.i("MainActivity", "URI NDEF message written successful ");




            /*ntag424DNA.getReader().setTimeout(timeOut);
            mStringBuilder.append(getString(R.string.Writing_data_to_Default_file));
            mStringBuilder.append("\n\n");
            ntag424DNA.setPICCConfiguration(true);
            mStringBuilder.append(getString(R.string.Data_to_write)).append(
                    Utilities.dumpBytes(data));
            mStringBuilder.append("\n\n");
            ntag424DNA.writeData(3, 0, data);
            mStringBuilder.append(getString(R.string.Data_written_successfully));
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_read_from_the_card)).append(
                    Utilities.dumpBytes(ntag424DNA.readData(3, 0, data.length)));
            mStringBuilder.append("\n\n");
            showMessage(mStringBuilder.toString(), PRINT);*/
            //To save the logs to file \sdcard\NxpLogDump\logdump.xml


            NxpLogUtils.save();
        } catch (Exception e) {
            writeFailedMessage();
            mStringBuilder.append(e.getMessage());
            showMessage(mStringBuilder.toString(), PRINT);
            NxpLogUtils.save();
        }

    }

    private void tag424DNATTCardLogic(INTAG424DNATT ntag424DNATT) {byte[] KEY_AES128_DEFAULT = {
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00
    };
        byte[] NTAG424DNA_APP_NAME =
                {(byte) 0xD2, (byte) 0x76, 0x00, 0x00, (byte) 0x85, 0x01, 0x01};
        byte[] data =
                {(byte) 0xA0, 0x00, 0x00, 0x03, (byte) 0x96, 0x56, 0x43, 0x41, 0x03, (byte) 0xF0,
                        0x15, 0x40, 0x00,
                        0x00, 0x00, 0x0B, (byte) 0xA0, 0x00, 0x00, 0x03, (byte) 0x96, 0x56, 0x43,
                        0x41, 0x03, (byte) 0xF0, 0x15,
                        0x40, 0x00, 0x00, 0x00, 0x0B};
        mStringBuilder.append(getString(R.string.Card_Detected)).append(
                ntag424DNATT.getType().getTagName());
        mStringBuilder.append("\n\n");
        int timeOut = 2000;
        try {
            ntag424DNATT.isoSelectApplicationByDFName(NTAG424DNA_APP_NAME);
            KeyData aesKeyData = new KeyData();
            Key keyDefault = new SecretKeySpec(KEY_AES128_DEFAULT, "AES");
            aesKeyData.setKey(keyDefault);
            ntag424DNATT.authenticateEV2First(0, aesKeyData, null);
            mStringBuilder.append(getString(R.string.Authentication_status_true));
            mStringBuilder.append("\n\n");
            ntag424DNATT.getReader().setTimeout(timeOut);
            mStringBuilder.append(getString(R.string.Writing_data_to_Default_file));
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_to_write)).append(
                    Utilities.dumpBytes(data));
            mStringBuilder.append("\n\n");
            ntag424DNATT.writeData(3, 0, data);

            mStringBuilder.append(getString(R.string.Data_written_successfully));
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_read_from_the_card)).append(
                    Utilities.dumpBytes(ntag424DNATT.readData(3, 0, data.length)));
            mStringBuilder.append("\n\n");
            showMessage(mStringBuilder.toString(), PRINT);
            //To save the logs to file \sdcard\NxpLogDump\logdump.xml
            NxpLogUtils.save();
        } catch (Exception e) {
            writeFailedMessage();
            mStringBuilder.append(e.getMessage());
            showMessage(mStringBuilder.toString(), PRINT);
            NxpLogUtils.save();
        }

    }


    private void ntag213TTCardLogic(final INTag213TagTamper ntag213TT) {
        mStringBuilder.append(getString(R.string.Card_Detected)).append(
                ntag213TT.getType().getTagName());
        mStringBuilder.append("\n\n");
        try {
            mStringBuilder.append(getString(R.string.Writing_data_at_page_number)).append(
                    PAGE_TO_READ_WRITE).append("...");
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_to_write)).append(
                    Utilities.dumpBytes(data));
            mStringBuilder.append("\n\n");
            ntag213TT.write(PAGE_TO_READ_WRITE, DATA_BYTES);
            mStringBuilder.append(getString(R.string.Data_written_successfully));
            mStringBuilder.append("\n\n");
            byte[] dataRead = ntag213TT.read(PAGE_TO_READ_WRITE);
            mStringBuilder.append(getString(R.string.Data_read_from_page)).append(
                    PAGE_TO_READ_WRITE).append(": ").append(
                    Utilities.dumpBytes(Arrays.copyOfRange(dataRead, 0, 4)));
            mStringBuilder.append("\n\n");
            showMessage(mStringBuilder.toString(), PRINT);
            //To save the logs to file \sdcard\NxpLogDump\logdump.xml
            NxpLogUtils.save();
        } catch (Exception e) {
            writeFailedMessage();
            mStringBuilder.append(e.getMessage());
            showMessage(mStringBuilder.toString(), PRINT);
            NxpLogUtils.save();
        }
    }

    /**
     * Ntag IO Operations.
     *
     * @param tag object
     */
    private void ntagCardLogic(final INTag tag) {
        tag.getReader().connect();
        mStringBuilder.append(getString(R.string.Card_Detected)).append(tag.getType().getTagName());
        mStringBuilder.append("\n\n");
        for (int idx = tag.getFirstUserpage(); idx <= 5; idx++) {
            try {
                byte[] dataWrite = new byte[]{(byte) idx, (byte) idx, (byte) idx, (byte) idx};
                mStringBuilder.append(getString(R.string.Writing_data_at_page_number)).append(
                        idx).append("...");
                mStringBuilder.append("\n\n");
                mStringBuilder.append(getString(R.string.Data_to_write)).append(
                        Utilities.dumpBytes(dataWrite));
                mStringBuilder.append("\n\n");
                tag.write(idx, dataWrite);
                mStringBuilder.append(
                        getString(R.string.Written_4_bytes_of_data_at_page_no)).append(idx).append(
                        ":").append(Utilities.dumpBytes(dataWrite));
                mStringBuilder.append("\n\n");
                showMessage(mStringBuilder.toString(), PRINT);
                //To save the logs to file \sdcard\NxpLogDump\logdump.xml
                NxpLogUtils.save();
            } catch (Exception e) {
                writeFailedMessage();
                mStringBuilder.append(e.getMessage());
                showMessage(mStringBuilder.toString(), PRINT);
                NxpLogUtils.save();
            }
        }
    }

    private void ultralightAESCardLogic(final IUltralightAES tag) {
        mStringBuilder.append(getString(R.string.Card_Detected)).append(tag.getType().getTagName());
        mStringBuilder.append("\n\n");
        //Setting the comm mode
        tag.setCommunicationMode(IUltralightAES.CommunicationMode.PLAIN);
        for (int idx = tag.getFirstUserpage(); idx <= 5; idx++) {
            try {
                byte[] dataWrite = new byte[]{(byte) idx, (byte) idx, (byte) idx, (byte) idx};
                mStringBuilder.append(getString(R.string.Writing_data_at_page_number)).append(
                        idx).append("...");
                mStringBuilder.append("\n\n");
                mStringBuilder.append(getString(R.string.Data_to_write)).append(
                        Utilities.dumpBytes(dataWrite));
                mStringBuilder.append("\n\n");
                tag.write(idx, dataWrite);
                mStringBuilder.append(
                        getString(R.string.Written_4_bytes_of_data_at_page_no)).append(idx).append(
                        ":").append(Utilities.dumpBytes(dataWrite));
                mStringBuilder.append("\n\n");
                showMessage(mStringBuilder.toString(), PRINT);
                //To save the logs to file \sdcard\NxpLogDump\logdump.xml
                NxpLogUtils.save();
            } catch (Exception e) {
                writeFailedMessage();
                mStringBuilder.append(e.getMessage());
                showMessage(mStringBuilder.toString(), PRINT);
                NxpLogUtils.save();
            }
        }
    }

    /**
     * ICode SLI card logic.
     */
    private void iCodeSLICardLogic(IICodeSLI icodeSLI) {
        icodeSLI.getReader().connect();
        byte[] readDataAfterWrite;
        mStringBuilder.append(getString(R.string.Card_Detected)).append(
                icodeSLI.getType().getTagName());
        mStringBuilder.append("\n\n");
        try {
            NdefMessageWrapper msg = new NdefMessageWrapper(createTextRecord(ndefData,
                    Locale.ENGLISH, false));
            mStringBuilder.append(getString(R.string.Writing_data_at_page_number)).append(
                    PAGE_TO_READ_WRITE).append("...");
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_to_write)).append(
                    Utilities.byteToHexString(
                            msg.toByteArray()));
            mStringBuilder.append("\n\n");
            icodeSLI.formatT5T();
            icodeSLI.writeNDEF(msg);
            mStringBuilder.append(R.string.Text_record_NDEF_written_successfully);
            mStringBuilder.append("\n\n");
            // write single block
            mStringBuilder.append(getString(R.string.Writing_single_block));
            mStringBuilder.append("\n\n");
            icodeSLI.writeSingleBlock(ICode.NFCV_FLAG_ADDRESS, DEFAULT_ICode_PAGE, DATA_BYTES);
            int nMblocks = icodeSLI.getNumBlocks();
            mStringBuilder.append(getString(R.string.No_of_blocks)).append(nMblocks);
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Written_4_bytes_of_data_at_page_no)).append(
                    "5: ").append(Utilities.dumpBytes(DATA_BYTES));
            mStringBuilder.append("\n\n");
            readDataAfterWrite = icodeSLI.readSingleBlock(ICode.NFCV_FLAG_ADDRESS,
                    DEFAULT_ICode_PAGE);
            if (null != readDataAfterWrite) {
                mStringBuilder.append(getString(R.string.Read_4_bytes_from_page_5)).append(
                        Utilities.dumpBytes(readDataAfterWrite));
            }
            showMessage(mStringBuilder.toString(), PRINT);
            //To save the logs to file \sdcard\NxpLogDump\logdump.xml
            NxpLogUtils.save();
        } catch (Exception e) {
            writeFailedMessage();
            mStringBuilder.append(e.getMessage());
            showMessage(mStringBuilder.toString(), PRINT);
            NxpLogUtils.save();
        }
    }

    /**
     * ICode SLIS card logic.
     */

    private void iCodeSLISCardLogic(IICodeSLIS icodeSLIS) {
        if (!icodeSLIS.getReader().isConnected()) {
            icodeSLIS.getReader().connect();
        }
        mStringBuilder.append(getString(R.string.Card_Detected)).append(
                icodeSLIS.getType().getTagName());
        mStringBuilder.append("\n\n");
        byte[] readAfterWrite;
        try {
            NdefMessageWrapper msg = new NdefMessageWrapper(createTextRecord(ndefData,
                    Locale.ENGLISH, false));
            mStringBuilder.append(getString(R.string.Writing_data_at_page_number)).append(
                    PAGE_TO_READ_WRITE).append("...");
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_to_write)).append(
                    Utilities.byteToHexString(
                            msg.toByteArray()));
            mStringBuilder.append("\n\n");
            icodeSLIS.formatT5T();
            icodeSLIS.writeNDEF(msg);
            mStringBuilder.append(R.string.Text_record_NDEF_written_successfully);
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Writing_single_block));
            mStringBuilder.append("\n\n");
            icodeSLIS.writeSingleBlock(ICode.NFCV_FLAG_ADDRESS, DEFAULT_ICode_PAGE,
                    DATA_BYTES);
            int nMblocks = icodeSLIS.getNumBlocks();
            mStringBuilder.append(getString(R.string.No_of_blocks)).append(nMblocks);
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Written_4_bytes_of_data_at_page_no)).append(
                    "5: ").append(Utilities.dumpBytes(DATA_BYTES));
            mStringBuilder.append("\n\n");
            readAfterWrite = icodeSLIS.readSingleBlock(ICode.NFCV_FLAG_ADDRESS, (byte) 0x05);
            if (null != readAfterWrite) {
                mStringBuilder.append(getString(R.string.Read_4_bytes_from_page_5)).append(
                        Utilities.dumpBytes(readAfterWrite));
            }
            showMessage(mStringBuilder.toString(), PRINT);
            //To save the logs to file \sdcard\NxpLogDump\logdump.xml
            NxpLogUtils.save();
        } catch (Exception e) {
            writeFailedMessage();
            mStringBuilder.append(e.getMessage());
            showMessage(mStringBuilder.toString(), PRINT);
            NxpLogUtils.save();
        }
    }

    /**
     * ICode SLIL card logic.
     */
    private void iCodeSLILCardLogic(IICodeSLIL icodeSLIL) {
        icodeSLIL.getReader().connect();
        mStringBuilder.append(getString(R.string.Card_Detected)).append(
                icodeSLIL.getType().getTagName());
        mStringBuilder.append("\n\n");
        byte[] readDataAfterWrite;
        try {
            NdefMessageWrapper msg = new NdefMessageWrapper(createTextRecord(ndefData,
                    Locale.ENGLISH, false));
            mStringBuilder.append(getString(R.string.Writing_data_at_page_number)).append(
                    PAGE_TO_READ_WRITE).append("...");
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_to_write)).append(
                    Utilities.byteToHexString(
                            msg.toByteArray()));
            mStringBuilder.append("\n\n");
            icodeSLIL.formatT5T();
            icodeSLIL.writeNDEF(msg);
            mStringBuilder.append(getString(R.string.Text_record_NDEF_written_successfully));
            mStringBuilder.append("\n\n");
            int nMblocks = icodeSLIL.getNumBlocks();
            mStringBuilder.append(getString(R.string.No_of_blocks)).append(nMblocks);
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Writing_single_block));
            mStringBuilder.append("\n\n");
            icodeSLIL.writeSingleBlock(ICode.NFCV_FLAG_ADDRESS, DEFAULT_ICode_PAGE, DATA_BYTES);
            mStringBuilder.append(getString(R.string.Written_4_bytes_of_data_at_page_no)).append(
                    "5").append(Utilities.dumpBytes(DATA_BYTES));
            readDataAfterWrite = icodeSLIL.readSingleBlock(ICode.NFCV_FLAG_ADDRESS,
                    DEFAULT_ICode_PAGE);
            if (null != readDataAfterWrite) {
                mStringBuilder.append(getString(R.string.Read_4_bytes_from_page_5)).append(
                        Utilities.dumpBytes(readDataAfterWrite));
            }
            showMessage(mStringBuilder.toString(), PRINT);
            //To save the logs to file \sdcard\NxpLogDump\logdump.xml
            NxpLogUtils.save();
        } catch (Exception e) {
            writeFailedMessage();
            mStringBuilder.append(e.getMessage());
            showMessage(mStringBuilder.toString(), PRINT);
            NxpLogUtils.save();
        }
    }

    /**
     * ICode SLIX card logic.
     */
    private void iCodeSLIXCardLogic(IICodeSLIX icodeSLIX) {
        icodeSLIX.getReader().connect();
        byte[] readDataAfterWrite;
        mStringBuilder.append(getString(R.string.Card_Detected)).append(
                icodeSLIX.getType().getTagName());
        mStringBuilder.append("\n\n");
        try {
            NdefMessageWrapper msg = new NdefMessageWrapper(createTextRecord(ndefData,
                    Locale.ENGLISH, false));
            mStringBuilder.append(getString(R.string.Writing_data_at_page_number)).append(
                    PAGE_TO_READ_WRITE).append("...");
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_to_write)).append(
                    Utilities.byteToHexString(
                            msg.toByteArray()));
            mStringBuilder.append("\n\n");
            icodeSLIX.formatT5T();
            icodeSLIX.writeNDEF(msg);
            mStringBuilder.append(getString(R.string.Text_record_NDEF_written_successfully));
            mStringBuilder.append(getString(R.string.Writing_single_block));
            mStringBuilder.append("\n\n");
            icodeSLIX.writeSingleBlock(ICode.NFCV_FLAG_ADDRESS, DEFAULT_ICode_PAGE, DATA_BYTES);
            int nMblocks = icodeSLIX.getNumBlocks();
            mStringBuilder.append(getString(R.string.No_of_blocks)).append(nMblocks);
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Written_4_bytes_of_data_at_page_no)).append(
                    "5").append(Utilities.dumpBytes(DATA_BYTES));
            mStringBuilder.append("\n\n");
            readDataAfterWrite = icodeSLIX.readSingleBlock(ICode.NFCV_FLAG_ADDRESS,
                    DEFAULT_ICode_PAGE);
            if (null != readDataAfterWrite) {
                mStringBuilder.append(getString(R.string.Read_4_bytes_from_page_5)).append(
                        Utilities.dumpBytes(readDataAfterWrite));
            }
            showMessage(mStringBuilder.toString(), PRINT);
            //To save the logs to file \sdcard\NxpLogDump\logdump.xml
            NxpLogUtils.save();
        } catch (Exception e) {
            writeFailedMessage();
            mStringBuilder.append(e.getMessage());
            showMessage(mStringBuilder.toString(), PRINT);
            NxpLogUtils.save();
        }
    }

    /**
     * ICode SLIXS card logic.
     */
    private void iCodeSLIXSCardLogic(IICodeSLIXS icodeSLIXS) {
        icodeSLIXS.getReader().connect();
        byte[] readDataAfterWrite;
        mStringBuilder.append(getString(R.string.Card_Detected)).append(
                icodeSLIXS.getType().getTagName());
        mStringBuilder.append("\n\n");
        try {
            NdefMessageWrapper msg = new NdefMessageWrapper(createTextRecord(ndefData,
                    Locale.ENGLISH, false));
            mStringBuilder.append(getString(R.string.Writing_data_at_page_number)).append(
                    PAGE_TO_READ_WRITE).append("...");
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_to_write)).append(
                    Utilities.byteToHexString(
                            msg.toByteArray()));
            mStringBuilder.append("\n\n");
            icodeSLIXS.formatT5T();
            icodeSLIXS.writeNDEF(msg);
            mStringBuilder.append(getString(R.string.Text_record_NDEF_written_successfully));
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Writing_single_block));
            mStringBuilder.append("\n\n");
            icodeSLIXS.writeSingleBlock(ICode.NFCV_FLAG_ADDRESS, DEFAULT_ICode_PAGE,
                    DATA_BYTES);
            int nMblocks = icodeSLIXS.getNumBlocks();
            mStringBuilder.append(getString(R.string.No_of_blocks)).append(nMblocks);
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Written_4_bytes_of_data_at_page_no)).append(
                    "5").append(Utilities.dumpBytes(DATA_BYTES));
            mStringBuilder.append("\n\n");
            readDataAfterWrite = icodeSLIXS.readSingleBlock(ICode.NFCV_FLAG_ADDRESS,
                    DEFAULT_ICode_PAGE);
            if (null != readDataAfterWrite) {
                mStringBuilder.append(getString(R.string.Read_4_bytes_from_page_5)).append(
                        Utilities.dumpBytes(readDataAfterWrite));
            }
            showMessage(mStringBuilder.toString(), PRINT);
            //To save the logs to file \sdcard\NxpLogDump\logdump.xml
            NxpLogUtils.save();
        } catch (Exception e) {
            writeFailedMessage();
            mStringBuilder.append(e.getMessage());
            showMessage(mStringBuilder.toString(), PRINT);
            NxpLogUtils.save();
        }
    }

    /**
     * ICode SLIXL card logic.
     */
    private void iCodeSLIXLCardLogic(IICodeSLIXL icodeSLIXL) {
        icodeSLIXL.getReader().connect();
        byte[] readDataAfterWrite;
        mStringBuilder.append(getString(R.string.Card_Detected)).append(
                icodeSLIXL.getType().getTagName());
        mStringBuilder.append("\n\n");
        try {
            NdefMessageWrapper msg = new NdefMessageWrapper(createTextRecord(ndefData,
                    Locale.ENGLISH, false));
            mStringBuilder.append(getString(R.string.Writing_data_at_page_number)).append(
                    PAGE_TO_READ_WRITE).append("...");
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_to_write)).append(
                    Utilities.byteToHexString(
                            msg.toByteArray()));
            mStringBuilder.append("\n\n");
            icodeSLIXL.formatT5T();
            icodeSLIXL.writeNDEF(msg);
            mStringBuilder.append(getString(R.string.Text_record_NDEF_written_successfully));
            mStringBuilder.append(getString(R.string.Writing_single_block));
            mStringBuilder.append("\n\n");
            icodeSLIXL.writeSingleBlock(ICode.NFCV_FLAG_ADDRESS, DEFAULT_ICode_PAGE,
                    DATA_BYTES);
            int nMblocks = icodeSLIXL.getNumBlocks();
            mStringBuilder.append(getString(R.string.No_of_blocks)).append(nMblocks);
            mStringBuilder.append(getString(R.string.Written_4_bytes_of_data_at_page_no)).append(
                    "5").append(Utilities.dumpBytes(DATA_BYTES));
            readDataAfterWrite = icodeSLIXL.readSingleBlock(ICode.NFCV_FLAG_ADDRESS,
                    DEFAULT_ICode_PAGE);
            if (null != readDataAfterWrite) {
                mStringBuilder.append(getString(R.string.Read_4_bytes_from_page_5)).append(
                        Utilities.dumpBytes(readDataAfterWrite));
            }
            showMessage(mStringBuilder.toString(), PRINT);
            //To save the logs to file \sdcard\NxpLogDump\logdump.xml
            NxpLogUtils.save();
        } catch (Exception e) {
            writeFailedMessage();
            mStringBuilder.append(e.getMessage());
            showMessage(mStringBuilder.toString(), PRINT);
            NxpLogUtils.save();
        }
    }

    /**
     * ICode SLIX2 card logic.
     */
    private void iCodeSLIX2CardLogic(IICodeSLIX2 icodeSLIX2) {
        byte[] readDataAfterWrite;
        mStringBuilder.append(getString(R.string.Card_Detected)).append(
                icodeSLIX2.getType().getTagName());
        mStringBuilder.append("\n\n");
        try {
            NdefMessageWrapper msg = new NdefMessageWrapper(createTextRecord(ndefData,
                    Locale.ENGLISH, false));
            mStringBuilder.append(getString(R.string.Writing_data_at_page_number)).append(
                    PAGE_TO_READ_WRITE).append("...");
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_to_write)).append(
                    Utilities.byteToHexString(
                            msg.toByteArray()));
            mStringBuilder.append("\n\n");
            icodeSLIX2.formatT5T();
            icodeSLIX2.writeNDEF(msg);
            mStringBuilder.append(getString(R.string.Text_record_NDEF_written_successfully));
            mStringBuilder.append(getString(R.string.Writing_single_block));
            mStringBuilder.append("\n\n");
            icodeSLIX2.writeSingleBlock(ICode.NFCV_FLAG_ADDRESS, DEFAULT_ICode_PAGE,
                    DATA_BYTES);
            int nMblocks = icodeSLIX2.getNumBlocks();
            mStringBuilder.append(getString(R.string.No_of_blocks)).append(nMblocks);
            mStringBuilder.append(getString(R.string.Written_4_bytes_of_data_at_page_no)).append(
                    "5").append(Utilities.dumpBytes(DATA_BYTES));
            readDataAfterWrite = icodeSLIX2.readSingleBlock(ICode.NFCV_FLAG_ADDRESS,
                    DEFAULT_ICode_PAGE);
            if (null != readDataAfterWrite) {
                mStringBuilder.append(getString(R.string.Read_4_bytes_from_page_5)).append(
                        Utilities.dumpBytes(readDataAfterWrite));
            }
            showMessage(mStringBuilder.toString(), PRINT);
            //To save the logs to file \sdcard\NxpLogDump\logdump.xml
            NxpLogUtils.save();
        } catch (Exception e) {
            writeFailedMessage();
            mStringBuilder.append(e.getMessage());
            showMessage(mStringBuilder.toString(), PRINT);
            NxpLogUtils.save();
        }
    }

    private void iCodeDNACardLogic(IICodeDNA icodeDNA) {
        byte[] readDataAfterWrite;
        mStringBuilder.append(getString(R.string.Card_Detected)).append(
                icodeDNA.getType().getTagName());
        mStringBuilder.append("\n\n");
        try {
            NdefMessageWrapper msg = new NdefMessageWrapper(createTextRecord(ndefData,
                    Locale.ENGLISH, false));
            mStringBuilder.append(getString(R.string.Writing_data_at_page_number)).append(
                    PAGE_TO_READ_WRITE).append("...");
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_to_write)).append(
                    Utilities.byteToHexString(
                            msg.toByteArray()));
            mStringBuilder.append("\n\n");
            icodeDNA.formatT5T();
            icodeDNA.writeNDEF(msg);
            mStringBuilder.append(getString(R.string.Text_record_NDEF_written_successfully));
            mStringBuilder.append(getString(R.string.Writing_single_block));
            mStringBuilder.append("\n\n");
            icodeDNA.writeSingleBlock(ICode.NFCV_FLAG_ADDRESS, DEFAULT_ICode_PAGE, DATA_BYTES);
            mStringBuilder.append(getString(R.string.Written_4_bytes_of_data_at_page_no)).append(
                    "5").append(Utilities.dumpBytes(DATA_BYTES));
            readDataAfterWrite = icodeDNA.readSingleBlock(ICode.NFCV_FLAG_ADDRESS,
                    DEFAULT_ICode_PAGE);
            int nMblocks = icodeDNA.getNumBlocks();
            mStringBuilder.append(getString(R.string.No_of_blocks)).append(nMblocks);
            if (null != readDataAfterWrite) {
                mStringBuilder.append(getString(R.string.Read_4_bytes_from_page_5)).append(
                        Utilities.dumpBytes(readDataAfterWrite));
            }
            showMessage(mStringBuilder.toString(), PRINT);
            //To save the logs to file \sdcard\NxpLogDump\logdump.xml
            NxpLogUtils.save();
        } catch (Exception e) {
            writeFailedMessage();
            mStringBuilder.append(e.getMessage());
            showMessage(mStringBuilder.toString(), PRINT);
            NxpLogUtils.save();
        }
    }

//    private void iNTagFiveCardLogic(INTAG5 intagFive) {
//        byte[] readDataAfterWrite;
//        mStringBuilder.append(getString(R.string.Card_Detected)).append(
//                intagFive.getType().getTagName());
//        mStringBuilder.append("\n\n");
//        try {
//            NdefMessageWrapper msg = new NdefMessageWrapper(createTextRecord(ndefData,
//                    Locale.ENGLISH, false));
//            mStringBuilder.append(getString(R.string.Writing_data_at_page_number)).append(
//                    PAGE_TO_READ_WRITE).append("...");
//            mStringBuilder.append("\n\n");
//            mStringBuilder.append(getString(R.string.Data_to_write)).append(
//                    Utilities.byteToHexString(
//                            msg.toByteArray()));
//            mStringBuilder.append("\n\n");
//            intagFive.formatT5T();
//            intagFive.writeNDEF(msg);
//            mStringBuilder.append(getString(R.string.Text_record_NDEF_written_successfully));
//            mStringBuilder.append(getString(R.string.Writing_single_block));
//            mStringBuilder.append("\n\n");
//            intagFive.writeSingleBlock(ICode.NFCV_FLAG_ADDRESS, DEFAULT_ICode_PAGE, DATA_BYTES);
//            mStringBuilder.append(getString(R.string.Written_4_bytes_of_data_at_page_no)).append(
//                    "5").append(Utilities.dumpBytes(DATA_BYTES));
//            readDataAfterWrite = intagFive.readSingleBlock(ICode.NFCV_FLAG_ADDRESS,
//                    DEFAULT_ICode_PAGE);
//            if (null != readDataAfterWrite) {
//                mStringBuilder.append(getString(R.string.Read_4_bytes_from_page_5)).append(
//                        Utilities.dumpBytes(readDataAfterWrite));
//            }
//            showMessage(mStringBuilder.toString(), PRINT);
//            //To save the logs to file \sdcard\NxpLogDump\logdump.xml
//            NxpLogUtils.save();
//        } catch (Exception e) {
//            writeFailedMessage();
//            mStringBuilder.append( e.getMessage());
//            showMessage(mStringBuilder.toString(), PRINT);
//            NxpLogUtils.save();
//        }
//    }

    private void mifareDUOXCardLogic(IMifareDUOX mifareDUOX) {
        mifareDUOX.getReader().connect();
        mifareDUOX.getReader().setTimeout(2000);

        KeyData keyDataAES128 = new KeyData();
        keyDataAES128.setKey(new SecretKeySpec(new byte[16], "AES"));
        KeyData keyDataAES256 = new KeyData();
        keyDataAES256.setKey(new SecretKeySpec(new byte[32], "AES"));
        byte[] Pub_CA_B = CustomModules.getUtility().hexStringToByte(
                "04776100D86A3738962A51D3BA5BC2BBF793F8F82E07BA597291F513F5D34282E71A3C7153678908B2FDC37CD6E182701731C34529E32D925CED1288262E6657D2");
        byte[] Priv_A = CustomModules.getUtility().hexStringToByte(
                "B49D8A23E10CE6FBBD16CC37D4A2B4E66E72B71E44C45C5E0A9720D77F8325EA");

        byte[] Cert_A = CustomModules.getUtility().hexStringToByte(
                "308201183081BFA003020102020401020304300A06082A8648CE3D040302301431123010060355042D03090043415F526F6F7430301E170D3234313231303037303832" +
                        "395A170D3234313231303037303832395A301531133011060355042D030A004C6561665F436572743059301306072A8648CE3D020106082A8648CE3D030107" +
                        "03420004587827DCE45AEDF98728841D97E85F0F603AD8FD3F70CD907C66153FDAC59FD79AC7F3E7BB3393E43815610D424F8F97B8A721E53C94A14480E562" +
                        "10D2FCC546300A06082A8648CE3D0403020348003045022054F4DFA93B4F77517CA9CBEDB5BF42DD63FBEDF1EE178FC0E5D5AEB2C5FE9F1D022100E93E3F0F" +
                        "A20690DB8F03D50178AC2656F725EFAB28696B320B63980E26C5AA38");

        byte[] Cert_B = CustomModules.getUtility().hexStringToByte(
                "1C0100308201183081BFA003020102020401020304300A06082A8648CE3D040302301431123010060355042D03090043415F526F6F7430301E170D3234313231" +
                        "303037303733345A170D3234313231303037303733345A301531133011060355042D030A004C6561665F436572743059301306072A8648CE3D020106082A8648CE3D03" +
                        "010703420004EC52DA08C1786BA3122868B13FF2F3FE4A821B5D2DF9A909CDA5B11062D335404A7B1D928F49C1F4A8D926D04249669468EE2EFF8CB8C5D2328170F54A" +
                        "880726300A06082A8648CE3D0403020348003045022100C346E0DBC4F045704274BE736BA45B3B7BCAABC343C9D242F247CDD7D4B2929C022027CFEB15E95C870B34D4" +
                        "92148E50D4B20BDA1CF4061ABCC67B86F68A36007C27");

        int fileSize = CustomModules.getUtility().bytesToInt(
                CustomModules.getUtility().hexStringToByte("1F0100"));

        byte[] privateKey0 = CustomModules.getUtility().hexStringToByte(
                "5FEB3DAE9EA017F7054036469693266DBE73B5B4A91724364CFA3EA42EB0E514");

        byte[] issuer = CustomModules.getUtility().hexStringToByte(
                "301431123010060355042D03090043415F526F6F7430");

        mStringBuilder.append(getString(R.string.Card_Detected)).append(
                mifareDUOX.getType().getTagName());
        mStringBuilder.append("\n\n");

        try {
            mStringBuilder.append("Personalize Tag for Asymmetric authentication at PICC level ");
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Selecting_PICC));
            mStringBuilder.append("\n\n");
            mifareDUOX.selectApplication(0);
            mStringBuilder.append(getString(R.string.PICC_selection_success));
            mStringBuilder.append("\n\n");

            mStringBuilder.append(getString(R.string.Auth_with_default_key));
            mStringBuilder.append("\n\n");
            mifareDUOX.authenticateEV2First(0x00, keyDataAES128, null);
            mStringBuilder.append(getString(R.string.Authentication_status_true));
            mStringBuilder.append("\n\n");

            mStringBuilder.append("Creating file to hold Cert.B if not already present.");
            mStringBuilder.append("\n\n");
            MifareDUOXFile.StdDataFileSettingsDUOX fileSettings =
                    new MifareDUOXFile.StdDataFileSettingsDUOX(IMifareDUOX.CommunicationType.Plain,
                            (byte) 0x0E, (byte) 0x0E, (byte) 0x0E, (byte) 0x0E, fileSize);
            byte[] isoFileIdStd = new byte[]{(byte) 0x80, (byte) 0x00};
            try {
                mifareDUOX.createFile(0, isoFileIdStd, fileSettings);
            } catch (Exception e){
                // Most cases in new card - could be file duplication error.
                mifareDUOX.authenticateEV2First(0x00, keyDataAES128, null);
                mifareDUOX.deleteFile(0);
                mifareDUOX.createFile(0, isoFileIdStd, fileSettings);
            }
            mStringBuilder.append("Creating file successful.");
            mStringBuilder.append("\n\n");
            mStringBuilder.append("Setting PICC Frame size 256");
            mStringBuilder.append("\n\n");
            mifareDUOX.setPICCFrameSize(PICCFrameSize.PICC_FRAME_SIZE_256);
            mStringBuilder.append("Writing Cert.B to the file.");
            mStringBuilder.append("\n\n");
            mifareDUOX.writeData(0, 0, Cert_B, IMifareDUOX.CommunicationType.Plain);
            mStringBuilder.append("Writing Cert.B to the file successful");
            mStringBuilder.append("\n\n");
            mStringBuilder.append("Manage CA Root key.");
            mStringBuilder.append("\n\n");
            byte[] accessRights = mifareDUOX.getAccessConditionsBytes(true, true,
                    true, true, false, false, false, false,
                    false, false, false, false, false, false);
            byte writeAccess = 0x3E; //CommMode and access right.
            byte readAccess = 0x3F; //CommMode and access right.
            mifareDUOX.manageCARootKey(1, IMifareDUOX.CurveID.NIST_P256, accessRights,
                    writeAccess, readAccess, false, (byte) 0, new byte[3], Pub_CA_B, issuer,
                    IMifareDUOX.CommunicationType.Enciphered);

            mStringBuilder.append("Manage CA Root key successful.");
            mStringBuilder.append("\n\n");

            mStringBuilder.append("Importing private key (ManageKeyPair Option 1).");
            mStringBuilder.append("\n\n");
            byte[] keyPolicyBytes = mifareDUOX.getKeyPolicyBytes(false,
                    true, true, false,
                    false, false);
            byte writeAccessKey0 = (byte) 0x30; // CommMode and access right required to update key.
            byte[] kucLimit = new byte[4]; // 0x00000000, KeyUsageCtrLimit disabled.
            mifareDUOX.importPrivateKey(0, IMifareDUOX.CurveID.NIST_P256, keyPolicyBytes,
                    writeAccessKey0, kucLimit, privateKey0, IMifareDUOX.CommunicationType.Enciphered);

            mStringBuilder.append("Importing private key successful.");
            mStringBuilder.append("\n\n");

            mStringBuilder.append("Performing Asymmetric authentication at PICC level - Key 1.");
            mStringBuilder.append("\n\n");
            mifareDUOX.selectApplication(0);
            GeneralAuthResponse generalAuthResponse =
                    mifareDUOX.isoGeneralAuthenticate(1, 0,
                            IMifareDUOX.AuthMethod.AsymmetricMutualAuthWithCertA, Cert_A, 0,
                            false, 0, Priv_A, Pub_CA_B, IMifareDUOX.CurveID.NIST_P256);
            List<X509Certificate> certB = generalAuthResponse.getCertB();
            mStringBuilder.append("Asymmetric authentication at PICC level successful.");
            mStringBuilder.append("\n\n");

            mStringBuilder.append(getString(R.string.Creating_application));
            mStringBuilder.append("\n\n");
            EV3ApplicationKeySettings.Builder builder = new EV3ApplicationKeySettings.Builder();
            builder.setKeyTypeOfApplicationKeys(KeyType.AES256);
            EV3ApplicationKeySettings applicationKeySettings = builder.build();
            byte[] appID = new byte[] {1, 0, 0};
            mifareDUOX.createApplication(appID, applicationKeySettings);
            mStringBuilder.append(getString(R.string.App_creation_success)).append(
                    Utilities.dumpBytes(appID));
            mStringBuilder.append("\n\n");

            mStringBuilder.append("Selecting the created application : ").append(
                    Utilities.dumpBytes(appID));
            mStringBuilder.append("\n\n");
            mifareDUOX.selectApplication(1);
            mStringBuilder.append("Selected the Application sucessfully.");
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Auth_with_default_key)).append(" of KeyType" +
                    ".AES256");
            mStringBuilder.append("\n\n");
            mifareDUOX.authenticateEV2First(0x00, keyDataAES256, null);
            mStringBuilder.append(getString(R.string.Authentication_status_true));
            mStringBuilder.append("\n\n");

            mStringBuilder.append("Creating file to hold Cert.B if not already present.");
            mStringBuilder.append("\n\n");
            mifareDUOX.createFile(0, fileSettings);
            mStringBuilder.append("Creating file successful.");
            mStringBuilder.append("\n\n");

            mStringBuilder.append("Writing Cert.B to the file.");
            mStringBuilder.append("\n\n");
            mifareDUOX.writeData(0, 0, Cert_B, IMifareDUOX.CommunicationType.Plain);
            mStringBuilder.append("Writing Cert.B to the file.");
            mStringBuilder.append("\n\n");

            mStringBuilder.append("Manage CA Root key.");
            mStringBuilder.append("\n\n");
            mifareDUOX.manageCARootKey(0, IMifareDUOX.CurveID.NIST_P256, accessRights,
                    writeAccess, readAccess, false, (byte) 0, new byte[3], Pub_CA_B, issuer,
                    IMifareDUOX.CommunicationType.Enciphered);
            mStringBuilder.append("Manage CA Root key successful.");
            mStringBuilder.append("\n\n");

            mStringBuilder.append("Importing private key (ManageKeyPair Option 1).");
            mStringBuilder.append("\n\n");
            mifareDUOX.importPrivateKey(0, IMifareDUOX.CurveID.NIST_P256, keyPolicyBytes,
                    writeAccessKey0, kucLimit, privateKey0, IMifareDUOX.CommunicationType.Enciphered);
            mStringBuilder.append("Importing private key successful.");
            mStringBuilder.append("\n\n");

            mStringBuilder.append("Selecting the created application : ").append(
                    Utilities.dumpBytes(appID));
            mStringBuilder.append("\n\n");
            mifareDUOX.selectApplication(1);
            mStringBuilder.append("Selected the Application sucessfully.");
            mStringBuilder.append("\n\n");

            mStringBuilder.append("Performing Asymmetric authentication at App level - Key 0");
            mStringBuilder.append("\n\n");
            generalAuthResponse = mifareDUOX.isoGeneralAuthenticate(0, 0,
                    IMifareDUOX.AuthMethod.AsymmetricMutualAuthWithCertA, Cert_A, 0,
                    false, 0, Priv_A, Pub_CA_B, IMifareDUOX.CurveID.NIST_P256);
            mStringBuilder.append("Asymmetric authentication at App level successful");
            mStringBuilder.append("\n\n");

            mStringBuilder.append("Performing File Operations");
            mStringBuilder.append("\n\n");
            MifareDUOXFile.StdDataFileSettingsDUOX fileSettingsStd =
                    new MifareDUOXFile.StdDataFileSettingsDUOX(IMifareDUOX.CommunicationType.Plain,
                            (byte) 0, (byte) 0, (byte) 0, (byte) 0, 50);
            mStringBuilder.append("Creating File : "+1);
            mStringBuilder.append("\n\n");
            mifareDUOX.createFile(1, fileSettingsStd);

            byte[] dataToWrite = new byte[30];
            Arrays.fill(dataToWrite, (byte) 0x12); //Random data for test

            mStringBuilder.append(getString(R.string.Writing_data_to_tag));
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_to_write)).append(
                    Utilities.dumpBytes(dataToWrite));
            mStringBuilder.append("\n\n");
            mifareDUOX.writeData(1, 0, dataToWrite, IMifareDUOX.CommunicationType.Plain);
            mStringBuilder.append(getString(R.string.Data_written_successfully));
            mStringBuilder.append("\n\n");
            mStringBuilder.append(getString(R.string.Data_read_from_the_card)).append(
                    Utilities.dumpBytes(mifareDUOX.readData(1, 0, 30)));
            mStringBuilder.append("\n\n");

            mStringBuilder.append("Deleting the file");
            mStringBuilder.append("\n\n");
            mifareDUOX.deleteFile(1);
            mStringBuilder.append("File deleted sucessfully.");
            mStringBuilder.append("\n\n");

            mStringBuilder.append(getString(R.string.Selecting_PICC));
            mStringBuilder.append("\n\n");
            mifareDUOX.selectApplication(0);
            mStringBuilder.append(getString(R.string.PICC_selection_success));
            mStringBuilder.append("\n\n");

            mStringBuilder.append("Asymmetric authentication at PICC level - Key 1.");
            mStringBuilder.append("\n\n");
            generalAuthResponse = mifareDUOX.isoGeneralAuthenticate(1, 0,
                    IMifareDUOX.AuthMethod.AsymmetricMutualAuthWithCertA, Cert_A, 0,
                    false, 0, Priv_A, Pub_CA_B, IMifareDUOX.CurveID.NIST_P256);
            mStringBuilder.append("Asymmetric authentication at PICC level successful.");
            mStringBuilder.append("\n\n");
            mStringBuilder.append("Deleting the Application : ").append(Utilities.dumpBytes(appID));
            mStringBuilder.append("\n\n");
            mifareDUOX.deleteApplication(1);
            mStringBuilder.append("Application deleted successfully.");
            mStringBuilder.append("\n\n");
            showMessage(mStringBuilder.toString(), PRINT);
            mifareDUOX.getReader().close();

            // Set the custom path where logs will get stored, here we are setting the log
            // folder DESFireLogs under external storage.
            String spath = Environment.getExternalStorageDirectory().getPath() + File.separator
                    + getString(R.string.DESFireLogs);
            NxpLogUtils.setLogFilePath(spath);
            // if you don't call save as below , logs will not be saved.
            NxpLogUtils.save();
        } catch (Exception e) {
            writeFailedMessage();
            mStringBuilder.append(e.getMessage());
            showMessage(mStringBuilder.toString(), PRINT);
            NxpLogUtils.save();
        }
    }

    @Override
    protected void onPause() {
        libInstance.stopForeGroundDispatch();
        super.onPause();
    }

    @Override
    protected void onResume() {
        libInstance.startForeGroundDispatch();
        super.onResume();
    }

    /**
     * Encrypt the supplied data with key provided.
     *
     * @param data data bytes to be encrypted
     * @param key  Key to encrypt the buffer
     * @return encrypted data bytes
     * @throws InvalidKeyException                InvalidKeyException
     * @throws IllegalBlockSizeException          IllegalBlockSizeException
     * @throws BadPaddingException                eption BadPaddingException
     * @throws InvalidAlgorithmParameterException InvalidAlgorithmParameterException
     */
    private byte[] encryptAESData(final byte[] data, final byte[] key)
            throws
            InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException {
        final SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
        return cipher.doFinal(data);
    }

    /**
     * @param encdata Encrypted input buffer.
     * @param key     Key to decrypt the buffer.
     * @return byte array.
     * @throws InvalidKeyException                if key is invalid.
     * @throws IllegalBlockSizeException          if block size is illegal.
     * @throws BadPaddingException                if padding is bad.
     * @throws InvalidAlgorithmParameterException if algo. is not avaliable or not present.
     */
    private byte[] decryptAESData(final byte[] encdata, final byte[] key)
            throws
            InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException {
        final SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);
        return cipher.doFinal(encdata);
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
                Toast.makeText(WriteActivity.this, str, Toast.LENGTH_SHORT)
                        .show();
                break;
            case PRINT:
                information_textView.setText(str);
                information_textView.setGravity(Gravity.START);
                NxpLogUtils.i(TAG, getString(R.string.Dump_data) + str);
                break;
            case TOAST_PRINT:
                Toast.makeText(WriteActivity.this, "\n" + str, Toast.LENGTH_SHORT).show();
                information_textView.setText(str);
                information_textView.setGravity(Gravity.START);
                NxpLogUtils.i(TAG, "\n" + str);
                break;
            default:
                break;
        }
    }

    private NdefRecordWrapper createTextRecord(String payload, Locale locale,
            boolean encodeInUtf8) {
        byte[] langBytes = locale.getLanguage().getBytes(
                Charset.forName(US_ASCII));
        Charset utfEncoding = encodeInUtf8 ? Charset.forName(UTF_8) : Charset
                .forName("UTF-16");
        byte[] textBytes = payload.getBytes(utfEncoding);
        int utfBit = encodeInUtf8 ? 0 : (1 << 7);
        char status = (char) (utfBit + langBytes.length);
        byte[] data = new byte[1 + langBytes.length + textBytes.length];
        data[0] = (byte) status;
        System.arraycopy(langBytes, 0, data, 1, langBytes.length);
        System.arraycopy(textBytes, 0, data, 1 + langBytes.length,
                textBytes.length);
        return new NdefRecordWrapper(NdefRecord.TNF_WELL_KNOWN,
                NdefRecord.RTD_TEXT, new byte[0], data);
    }

    private void writeFailedMessage() {
        mStringBuilder.append(getString(R.string.Unable_to_perfom_to_operation));
        mStringBuilder.append("\n\n");
        information_textView.setText(mStringBuilder);
        information_textView.setGravity(Gravity.START);
    }

    @Override
    public void onBackPressed() {
        super.onBackPressed();
        Intent intent = new Intent(WriteActivity.this, MainActivity.class);
        //this is used as activity class is subclass of Context
        startActivity(intent);
        finish();
    }
}
