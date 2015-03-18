package helloCryptCard;

import javacard.framework.APDU;
import javacard.framework.APDUException;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.TransactionException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 *
 * @author MATYSIAK Herve <herve.matysiak@viacesi.fr>
 */
public class helloCryptCard extends Applet {

    //CLA ID
    static final byte CLA_APPLET = (byte) 0xB0;

    //APPLET STATE
    static final byte STATE_INIT = 0;
    static final byte STATE_ISSUED = 1;

    ////INSTRUCTION
    //INIT
    static final byte INS_SET_PUBLIC_MODULUS = (byte) 0x01;
    static final byte INS_SET_PRIVATE_MODULUS = (byte) 0x02;
    static final byte INS_SET_PRIVATE_EXP = (byte) 0x03;
    static final byte INS_SET_PUBLIC_EXP = (byte) 0x04;
    static final byte INS_TEST_PUBLIC_KEY = (byte) 0x05;
    static final byte INS_TEST_PRIVATE_KEY = (byte) 0x06;
    static final byte INS_SET_ISSUED = (byte) 0x07;
    //ISSUED
    static final byte INS_SESSION_INIT = (byte) 0x10;
    static final byte INS_MESSAGE = (byte) 0x20;

    ////STATUS WORD
    final static short SW_PULBIC_KEY_FAILED = 0x6300;
    final static short SW_PRIVATE_KEY_FAILED = 0x6301;
    final static short SW_SESSION_KEY_FAILED = 0x6303;
    final static short SW_SESSION_KEY_NOT_VALID = 0x6304;
    final static short SW_MAGIC_KEY_NOT_VALID = 0x6305;

    //DATA
    static final byte MAGIC_VALUE = (byte) 0x5f3759df;
    static final byte[] MAGIC_STRING = {(byte) 0x43, (byte) 0x41, (byte) 0x46,
        (byte) 0x45, (byte) 0x20, (byte) 0x49, (byte) 0x53, (byte) 0x20, (byte) 0x54,
        (byte) 0x48, (byte) 0x45, (byte) 0x20, (byte) 0x42, (byte) 0x45, (byte) 0x53,
        (byte) 0x54};
    private byte state;
    private byte[] sessionKey;
    byte[] tmp;

    //SECURITY
    DESKey desKey;
    RandomData randomDataGenerator;
    RSAPrivateKey privateKey;
    RSAPublicKey publicKey;
    Cipher cipherRSA;
    Cipher cipherDES;
    Signature signature;

    //BEHAVIOR
    /**
     * Installs this applet.
     *
     * @param bArray the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new helloCryptCard(bArray, bOffset, bLength);
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected helloCryptCard(byte[] bArray, short bOffset, byte bLength) {
        //Cipher
        cipherRSA = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        cipherDES = Cipher.getInstance(Cipher.ALG_DES_ECB_PKCS5, false);
        //Sign
        signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        //Session
        desKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_DES3_2KEY, false);
        sessionKey = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
        //Crypt
        privateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
        publicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
        privateKey.clearKey();
        publicKey.clearKey();
        //RandomData
        randomDataGenerator = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        //Applet State
        state = STATE_INIT;
        //TMP
        tmp = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_RESET);
        //register
        register();
    }

    /**
     * Processes an incoming APDU.
     *
     * @see APDU
     * @param apdu the incoming APDU
     */
    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        //APPLET Selection
        if (selectingApplet()) {
            return;
        }

        //Read Bin Only
        if (buffer[ISO7816.OFFSET_CLA] != CLA_APPLET) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        byte ins = buffer[ISO7816.OFFSET_INS];

        switch (state) {
            case STATE_INIT:
                switch (ins) {
                    case INS_SET_PUBLIC_MODULUS:
                        insSetPublicModulus(apdu);
                        break;
                    case INS_SET_PRIVATE_MODULUS:
                        insSetPrivateModulus(apdu);
                        break;
                    case INS_SET_PUBLIC_EXP:
                        insSetPublicExp(apdu);
                        break;
                    case INS_SET_PRIVATE_EXP:
                        insSetPrivateExp(apdu);
                        break;
                    case INS_TEST_PUBLIC_KEY:
                        insTestPublicKey(apdu);
                        break;
                    case INS_TEST_PRIVATE_KEY:
                        insTestPrivateKey(apdu);
                        break;
                    case INS_SET_ISSUED:
                        insSetIssued();
                        break;
                    default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                }
                break;
            case STATE_ISSUED: {
                if (ins == INS_SESSION_INIT) {
                    insSessionInit(apdu);
                } else {
                    if (!desKey.isInitialized()) {
                        ISOException.throwIt(SW_SESSION_KEY_NOT_VALID);
                    }
                    switch (ins) {
                        case INS_MESSAGE:
                            insMessage(apdu);
                            break;
                        default:
                            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                    }
                }
                break;
            }
            default:
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
    }

    /**
     * Set Modulus of public key
     *
     * @param apdu
     * @param lc
     */
    void insSetPublicModulus(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        try {
            JCSystem.beginTransaction();
            publicKey.setModulus(buffer, ISO7816.OFFSET_CDATA, (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF));
            JCSystem.commitTransaction();
        } catch (CryptoException ex) {
            JCSystem.abortTransaction();
            ISOException.throwIt((short) (0x9100 + ex.getReason()));
        } catch (TransactionException ex) {
            ISOException.throwIt((short) (0x9200 + ex.getReason()));
        }
    }

    /**
     * Set Modulus of private key
     *
     * @param apdu
     * @param lc
     */
    void insSetPrivateModulus(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        try {
            JCSystem.beginTransaction();
            privateKey.setModulus(buffer, ISO7816.OFFSET_CDATA, (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF));
            JCSystem.commitTransaction();
        } catch (CryptoException ex) {
            JCSystem.abortTransaction();
            ISOException.throwIt((short) (0x9100 + ex.getReason()));
        } catch (TransactionException ex) {
            ISOException.throwIt((short) (0x9200 + ex.getReason()));
        }
    }

    /**
     * Set Exponent of private key
     *
     * @param apdu
     * @param lc
     */
    void insSetPrivateExp(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        try {
            JCSystem.beginTransaction();
            privateKey.setExponent(buffer, ISO7816.OFFSET_CDATA, (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF));
            JCSystem.commitTransaction();
        } catch (CryptoException ex) {
            JCSystem.abortTransaction();
            ISOException.throwIt((short) (0x9100 + ex.getReason()));
        } catch (TransactionException ex) {
            ISOException.throwIt((short) (0x9200 + ex.getReason()));
        }
    }

    /**
     * Set Exponent of public key
     *
     * @param apdu
     * @param lc
     */
    void insSetPublicExp(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        try {
            JCSystem.beginTransaction();
            publicKey.setExponent(buffer, ISO7816.OFFSET_CDATA, (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF));
            JCSystem.commitTransaction();
        } catch (CryptoException ex) {
            JCSystem.abortTransaction();
            ISOException.throwIt((short) (0x9100 + ex.getReason()));
        } catch (TransactionException ex) {
            ISOException.throwIt((short) (0x9200 + ex.getReason()));
        }
    }

    /**
     * Test if the Public key is initialized
     *
     * @param apdu
     */
    void insTestPublicKey(APDU apdu) {
        if (publicKey != null && !publicKey.isInitialized()) {
            ISOException.throwIt(SW_PULBIC_KEY_FAILED);
        }
    }

    /**
     * Test if the Private key is initialized
     *
     * @param apdu
     */
    void insTestPrivateKey(APDU apdu) {
        if (privateKey != null && !privateKey.isInitialized()) {
            ISOException.throwIt(SW_PRIVATE_KEY_FAILED);
        }
    }

    /**
     * Init the session Generate a random DES Key Crypt it Sign it
     *
     * @param apdu
     */
    void insSessionInit(APDU apdu) {
        try {
            randomDataGenerator.generateData(tmp, (short) 0, (short) 25);
            randomDataGenerator.setSeed(tmp, (short) 0, (short) 25);
            randomDataGenerator.generateData(sessionKey, (short) 0, (short) 16);
            JCSystem.beginTransaction();
            desKey.setKey(sessionKey, (short) 0);
            JCSystem.commitTransaction();

            byte[] buffer = apdu.getBuffer();
            short outCryptBuffSize = 0;
            short outSignBuffSize = 0;

            //Crypting
            cipherRSA.init(publicKey, Cipher.MODE_ENCRYPT);
            outCryptBuffSize = cipherRSA.doFinal(sessionKey, (short) 0, (short) 16, buffer, ISO7816.OFFSET_CDATA);

            //Signing
            signature.init(privateKey, Signature.MODE_SIGN);
            outSignBuffSize = signature.sign(buffer, ISO7816.OFFSET_CDATA, outCryptBuffSize, buffer, (short) (ISO7816.OFFSET_CDATA + outCryptBuffSize));

            short totalSize = (short) (outCryptBuffSize + outSignBuffSize);
            apdu.setOutgoing();
            apdu.setOutgoingLength(totalSize);
            apdu.sendBytes(ISO7816.OFFSET_CDATA, totalSize);

        } catch (CryptoException | TransactionException | NullPointerException | ArrayIndexOutOfBoundsException | APDUException ex) {
            JCSystem.abortTransaction();
            ISOException.throwIt(SW_SESSION_KEY_FAILED);
        } finally {
            Util.arrayFillNonAtomic(sessionKey, (short) 0, (short) 16, (byte) 0);
            Util.arrayFillNonAtomic(tmp, (short) 0, (short) 25, (byte) 0);
        }
    }

    /**
     * Get message Verify is MAGIC VALUE is set Add a custom string :)
     *
     * @param apdu
     */
    void insMessage(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short outCryptBuffSize = 0;
        short numBytes = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);

        cipherDES.init(desKey, Cipher.MODE_DECRYPT);
        outCryptBuffSize = cipherDES.doFinal(buffer, ISO7816.OFFSET_CDATA, numBytes, tmp, (short) 0);

        if (tmp[0] != MAGIC_VALUE) {
            ISOException.throwIt(SW_MAGIC_KEY_NOT_VALID);
        }

        outCryptBuffSize = Util.arrayCopyNonAtomic(MAGIC_STRING, (short) 0, tmp, outCryptBuffSize, (short) MAGIC_STRING.length);

        cipherDES.init(desKey, Cipher.MODE_ENCRYPT);
        outCryptBuffSize = cipherDES.doFinal(tmp, (short) 0, outCryptBuffSize, buffer, ISO7816.OFFSET_CDATA);

        apdu.setOutgoing();
        apdu.setOutgoingLength(outCryptBuffSize);
        apdu.sendBytes(ISO7816.OFFSET_CDATA, outCryptBuffSize);
    }

    /**
     * Set tha APP as Issued
     */
    void insSetIssued() {
        state = STATE_ISSUED;
    }

    public boolean select() {
        return true;
    }

    public void deselect() {
    }
}
