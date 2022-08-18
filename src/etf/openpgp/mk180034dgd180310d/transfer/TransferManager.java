package etf.openpgp.mk180034dgd180310d.transfer;

import etf.openpgp.mk180034dgd180310d.key_manager.KeyManager;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;

public class TransferManager {

    // Constants #######################################################################################################

    private static final int BUFFER_SIZE = 65535;

    // End Constants ###################################################################################################

    // construction of objects of transfer manager is forbidden
    private TransferManager() {

    }

    // Static data #####################################################################################################

    // encryption errors
    private static String signatureError = null;

    // decryption errors
    private static String decryptionError = null;
    private static String integrityError = null;

    // verify signature
    private static String signatureVerificationStatus = null;

    // static init block
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // End Static data #################################################################################################


    // Public methods ##################################################################################################

    /**
     * Message receiving
     *
     * @param outputFileName name of a new file where sent data will be stored after processing
     * @param inputFileName name of a file that should be sent
     * @param secretKeyId sending users encrypted private used for making signature
     * @param publicKeyId receivers public key used for encryption
     * @param encryptionAlgorithm algorithm used for encryption (Triple-DES or AES-128)
     * @param radix64Enabled is radix64 conversion enabled
     * @param encryptionEnabled is encryption enabled
     * @param compressionEnabled is compression enabled
     * @param signEnabled is signature enabled
     * @param passwd sending users password used to get his private key by decrypting his secret key
     * @throws IOException
     */
    public static void sendData(
            String outputFileName,
            String inputFileName,
            long secretKeyId,
            long publicKeyId,
            int encryptionAlgorithm,
            boolean radix64Enabled,
            boolean encryptionEnabled,
            boolean compressionEnabled,
            boolean signEnabled,
            char[] passwd)
            throws IOException {
        try {
            signatureError = null;

            OutputStream finalOutStream = new BufferedOutputStream(new FileOutputStream(outputFileName));

            if (radix64Enabled) {
                finalOutStream = new ArmoredOutputStream(finalOutStream);
            }

            OutputStream encryptOutStream = finalOutStream;
            PGPEncryptedDataGenerator encryptedDataGen = null;
            if (encryptionEnabled) {
                Iterator<PGPPublicKey> publicKeyIterator = KeyManager.getPublicKeyRingCollection()
                        .getPublicKeyRing(publicKeyId)
                        .getPublicKeys();

                // skip master key
                publicKeyIterator.next();

                // get subkey
                PGPPublicKey receiverPublicKey = publicKeyIterator.next();

                encryptedDataGen = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(encryptionAlgorithm)
                        .setWithIntegrityPacket(true)
                        .setSecureRandom(new SecureRandom())
                        .setProvider("BC"));
                encryptedDataGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(receiverPublicKey)
                        .setProvider("BC"));
                encryptOutStream = encryptedDataGen.open(finalOutStream, new byte[1 << 16]);
            }

            OutputStream compressionOutStream = encryptOutStream;
            PGPCompressedDataGenerator compressedDataGen = null;
            if (compressionEnabled) {
                compressedDataGen = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
                compressionOutStream = compressedDataGen.open(encryptOutStream);
            }

            PGPSignatureGenerator signGen = null;
            if (signEnabled) {
                PGPSecretKey senderSecretKey = KeyManager.getPrivateKeyRingCollection()
                        .getSecretKeyRing(secretKeyId)
                        .getSecretKeys()
                        .next();
                PGPPrivateKey senderPrivateKey = null;
                try {
                    senderPrivateKey = senderSecretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
                            .setProvider("BC")
                            .build(passwd));
                } catch (PGPException e) {
                    e.printStackTrace();
                }

                if (senderPrivateKey == null) {
                    TransferManager.signatureError = "Invalid password.";
                    return;
                }

                signGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(
                        senderSecretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1)
                        .setProvider("BC"));

                signGen.init(PGPSignature.BINARY_DOCUMENT, senderPrivateKey);

                Iterator users = senderSecretKey.getPublicKey().getUserIDs();
                if (users.hasNext()) {
                    PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
                    spGen.addSignerUserID(false, (String) users.next());
                    signGen.setHashedSubpackets(spGen.generate());
                }

                signGen.generateOnePassVersion(false).encode(compressionOutStream);
            }

            PGPLiteralDataGenerator literalDataGen = new PGPLiteralDataGenerator();
            OutputStream literalDataGenOutStream = literalDataGen
                    .open(compressionOutStream, PGPLiteralData.BINARY, new File(inputFileName));
            FileInputStream inStream = new FileInputStream(inputFileName);

            byte[] buffer = new byte[BUFFER_SIZE];
            int len;
            while ((len = inStream.read(buffer)) > 0) {
                literalDataGenOutStream.write(buffer, 0, len);

                if (signEnabled) {
                    signGen.update(buffer, 0, len);
                }
            }

            inStream.close();
            literalDataGenOutStream.close();
            if (signEnabled) {
                signGen.generate().encode(compressionOutStream);
            }
            compressionOutStream.close();
            if (compressionEnabled) {
                compressedDataGen.close();
            }
            encryptOutStream.close();
            if (encryptionEnabled) {
                encryptedDataGen.close();
            }
            finalOutStream.close();
        } catch (PGPException e) {
            System.err.println(e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }

    /**
     * Message receiving
     *
     * @param inputFileName name of the file that should be received
     * @param outputFileName name of the file where received file will be stored after processing
     * @param passwd password of a receiving user's private key in case file was encrypted
     * @throws IOException
     */
    public static void receiveData(
            String inputFileName,
            String outputFileName,
            char[] passwd)
            throws IOException {
        try {
            decryptionError = null;
            integrityError = null;
            signatureVerificationStatus = null;

            InputStream bufferedInStream = new BufferedInputStream(new FileInputStream(inputFileName));
            InputStream inStream = PGPUtil.getDecoderStream(bufferedInStream);
            OutputStream outStreamFinal = new BufferedOutputStream(new FileOutputStream(outputFileName));
            ByteArrayOutputStream outStreamCurrent = new ByteArrayOutputStream();

            PGPPublicKeyEncryptedData encryptedData = null;
            PGPOnePassSignatureList onePassSignatureList = null;
            PGPSignatureList signatureList = null;

            PGPSecretKeyRingCollection secretKeys = KeyManager.getPrivateKeyRingCollection();

            JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(inStream);

            Object data;
            try {
                data = objectFactory.nextObject();
            } catch (IOException e) {
                TransferManager.integrityError = "Lost message integrity.";
                return;
            }

            while (data != null) {
                if (data instanceof PGPEncryptedDataList) {
                    Iterator keys = ((PGPEncryptedDataList) data).getEncryptedDataObjects();
                    PGPPrivateKey myPrivateKey = null;

                    try {
                        while (myPrivateKey == null && keys.hasNext()) {
                            encryptedData = (PGPPublicKeyEncryptedData) keys.next();
                            myPrivateKey = findSecretKey(secretKeys, encryptedData.getKeyID(), passwd);
                        }
                    } catch (PGPException e) {
                        TransferManager.decryptionError = "Wrong password for private key.";
                        return;
                    }

                    if (myPrivateKey == null) {
                        TransferManager.decryptionError = "Private key not found in collection.";
                        return;
                    }

                    InputStream decrypted = encryptedData.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder()
                            .setProvider("BC")
                            .build(myPrivateKey));

                    objectFactory = new JcaPGPObjectFactory(decrypted);
                } else if (data instanceof PGPCompressedData) {
                    PGPCompressedData compressedData = (PGPCompressedData) data;
                    objectFactory = new JcaPGPObjectFactory(compressedData.getDataStream());
                } else if (data instanceof PGPOnePassSignatureList) {
                    onePassSignatureList = (PGPOnePassSignatureList) data;
                } else if (data instanceof PGPLiteralData) {
                    Streams.pipeAll(((PGPLiteralData) data).getInputStream(), outStreamCurrent);
                    outStreamCurrent.close();
                } else if (data instanceof PGPSignatureList) {
                    signatureList = (PGPSignatureList) data;
                } else {
                    TransferManager.integrityError = "Lost message integrity.";
                    throw new PGPException("Unknown message type");
                }
                data = objectFactory.nextObject();
            }

            if (onePassSignatureList != null && signatureList != null) {
                PGPOnePassSignature onePassSignature = onePassSignatureList.get(0);
                PGPPublicKey publicKey = KeyManager.getPublicKeyRingCollection()
                        .getPublicKey(onePassSignature.getKeyID());
                if (publicKey != null) {
                    onePassSignature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);
                    onePassSignature.update(outStreamCurrent.toByteArray());
                    PGPSignature signature = signatureList.get(0);
                    if (onePassSignature.verify(signature)) {
                        TransferManager.signatureVerificationStatus = "Signature verification successful.";
                    } else {
                        TransferManager.signatureVerificationStatus = "Signature verification failed.";
                        throw new PGPException("Signature verification failed.");
                    }
                }
            }

            if (encryptedData != null && encryptedData.isIntegrityProtected() && !encryptedData.verify()) {
                TransferManager.integrityError = "Lost message integrity.";
                throw new PGPException("Lost message integrity.");
            } else {
                outStreamFinal.write(outStreamCurrent.toByteArray());
                outStreamFinal.flush();
            }

            inStream.close();
        } catch (PGPException e) {
            System.err.println(e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }

    /**
     * Checks if file is encrypted or corrupted
     *
     * @param file file that should be checked
     * @return
     * @throws IOException
     */
    public static boolean isFileEncrypted(File file) throws IOException {
        InputStream bufferedInStream = new BufferedInputStream(new FileInputStream(file));
        InputStream inStream = PGPUtil.getDecoderStream(bufferedInStream);

        JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(inStream);
        Object data;
        try {
            data = objectFactory.nextObject();
        } catch (IOException e) {
            TransferManager.integrityError = "Lost message integrity.";
            return false;
        }

        inStream.close();

        return data instanceof PGPEncryptedDataList;
    }

    public static String getDecryptionError() {
        return decryptionError;
    }

    public static String getIntegrityError() {
        return integrityError;
    }

    public static String getSignatureError() {
        return signatureError;
    }

    public static String getSignatureVerificationStatus() {
        return signatureVerificationStatus;
    }

    // End Public methods ##############################################################################################


    // Private methods #################################################################################################

    /**
     * Search a secret key ring collection for a secret key corresponding to
     * keyID if it exists.
     *
     * @param pgpSec a secret key ring collection.
     * @param keyID keyID we want.
     * @param pass passphrase to decrypt secret key with.
     * @return the private key.
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    private static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass)
            throws PGPException {
        PGPSecretKey secKey = pgpSec.getSecretKey(keyID);

        if (secKey == null) {
            return null;
        }

        return secKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
    }

    // End Private methods #############################################################################################

//    public static void main(String[] args) throws Exception {
//        TransferManager.sendData("encryptedMsg.asc", "test.txt",
//                0x10B68F96448CA2FEL, 0x74F09986580C955DL, PGPEncryptedData.TRIPLE_DES,
//                true, true, true,
//                true, "12345".toCharArray());
//
//        TransferManager.receiveData("encryptedMsg.asc", "decryptedMsg.txt", "123".toCharArray());
//    }

}
