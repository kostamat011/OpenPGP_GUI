package etf.openpgp.mk180034dgd180310d.key_manager;


import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.jcajce.JcaPGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.*;

import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import java.io.*;
import java.security.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;

public class KeyManager {

    // Constants #######################################################################################################

    // key rings storage paths
    private static final String PRIVATE_RING_PATH = "./privates.asc";
    private static final String PUBLIC_RING_PATH = "./publics.asc";

    // End Constants ###################################################################################################

    // construction of objects of key manager is forbidden
    private KeyManager() {

    }

    // Static data #####################################################################################################

    // key ring collections
    private static PGPPublicKeyRingCollection publicKeys;
    private static PGPSecretKeyRingCollection privateKeys;
    private static String currentError;

    // static init block
    static {
        loadKeyRingsCollections();
        Security.addProvider(new BouncyCastleProvider());
    }

    // End Static data #################################################################################################

    // Public methods ##################################################################################################

    /**
     * Import a single key ring
     * @param file File that contains key ring
     * @param isPublic True for public key rings, false for private key rings
     * @return 0 on successful import, 1 on failed
     */
    public static int importKeyRing(File file, boolean isPublic) {
        if(!file.exists() || file.isDirectory()) {
            return 1;
        }
        try {
            ArmoredInputStream ain = new ArmoredInputStream(new FileInputStream(file));
            loadSingleKeyRing(ain, isPublic);
            ain.close();
            currentError = null;
            return 0;
        } catch (Exception err) {
            err.printStackTrace();
            currentError = err.getMessage();
            return 1;
        }
    }

    /**
     * Export a signle key ring
     * @param path Path to where to export key
     * @param keyId Id of the key to export
     * @param isPublic True for public key rings, false for private key rings
     * @return 0 on successful export, 1 on failed
     */
    public static int exportKeyRing(String path, long keyId, boolean isPublic) {

        // generate .asc file with name '{publicKey}/{privateKey}<keyId>.asc' on received path
        String fileName = ((isPublic) ? "publicKey" : "privateKey") + Long.toHexString(keyId) + ".asc";

        File file = new File(path, fileName);
        try{
            ArmoredOutputStream aout = new ArmoredOutputStream(new FileOutputStream(file));
            storeSingleKeyRing(aout,keyId,isPublic);
            aout.close();
            currentError = null;
            return 0;
        } catch (Exception err) {
            err.printStackTrace();
            currentError = err.getMessage();
            return 1;
        }
    }

    /**
     * Drops a private or public key ring from corresponding collection
     * @param keyId Id of the key to delete
     * @param isPublic True for public key rings, false for private key rings
     * @param passphrase Only needed for dropping private key
     * @return 0 on successful delete, 1 on failed
     */
    public static int deleteKeyRing(long keyId, boolean isPublic, String passphrase) {
        try {
            if(isPublic) {
                dropSinglePublicKeyRing(keyId);
            } else {
                dropSinglePrivateKeyRing(keyId, passphrase);
            }
            currentError = null;
            return 0;
        } catch (Exception err) {
            err.printStackTrace();
            currentError = err.getMessage();
            return 1;
        }
    }

    /**
     * Generate a new public/private key ring pair
     * @param userName user name
     * @param userEmail user email
     * @param passphrase password to protect private key
     * @param rsaEncryptKeySize size of RSA keypair for encryption in bits (1024,2048,4096)
     * @param rsaSignKeySize size of RSA keypair for signing in bits (1024,2048,4096)
     * @return 0 on success, 1 on failed
     */
    public static int generateNewKeyRingPair(String userName, String userEmail, String passphrase,
                                             int rsaEncryptKeySize, int rsaSignKeySize) {

        try {
            // generate RSA key pairs for encryption and signing
            KeyPair encryptionKeys = generateRSAKeyPair(rsaEncryptKeySize);
            KeyPair signingKeys = generateRSAKeyPair(rsaSignKeySize);

            // user identity is formed as: name <email>
            String user = userName + " <" + userEmail + ">";

            // generate PGPKeyPairs from generated key pairs
            // encryption keypair becomes primary (master)
            // signing keypair becomes sub
            PGPKeyPair primaryKeyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_SIGN, signingKeys, new Date());
            PGPKeyPair subKeyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, encryptionKeys, new Date());

            // generate digest calculator
            PGPDigestCalculator sha1DC =
                    new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

            // generate secret key encryptor
            PBESecretKeyEncryptor passEncryptor =
                    new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5,sha1DC)
                            .setProvider("BC").build(passphrase.toCharArray());

            // generate signer builder
            PGPContentSignerBuilder signerBuilder =
                    new JcaPGPContentSignerBuilder(primaryKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1);

            // create a key ring generator
            PGPKeyRingGenerator keyRingGenerator = new PGPKeyRingGenerator(
                    PGPSignature.POSITIVE_CERTIFICATION,
                    primaryKeyPair,
                    user,
                    sha1DC,
                    null,
                    null,
                    signerBuilder,
                    passEncryptor
            );

            // add subkey for signing to key ring generator
            keyRingGenerator.addSubKey(subKeyPair);

            // generate key rings
            PGPPublicKeyRing publicRing = keyRingGenerator.generatePublicKeyRing();
            PGPSecretKeyRing privateRing = keyRingGenerator.generateSecretKeyRing();

            // add key rings to collections
            addKeyRingToCollection(publicRing, true);
            addKeyRingToCollection(privateRing, false);

            currentError = null;
            return 0;
        } catch (Exception err) {
            err.printStackTrace();
            currentError = err.getMessage();
            return 1;
        }
    }

    /**
     * Get user identity for owner of public key ring
     * @param keyId Id of key
     * @return User identity string
     * @throws PGPException
     */
    public static String getUserIdentityForPublicKey(long keyId)
            throws PGPException {

        PGPPublicKeyRing ring = publicKeys.getPublicKeyRing(keyId);
        if(ring == null) {
            return null;
        }
        return ring.getPublicKey().getUserIDs().next();
    }

    /**
     * Get user identity for owner of private key ring
     * @param keyId Id of key
     * @return User identity string
     * @throws PGPException
     */
    public static String getUserIdentityForPrivateKey(long keyId)
        throws PGPException {

        PGPSecretKeyRing ring = privateKeys.getSecretKeyRing(keyId);
        if(ring == null) {
            return null;
        }
        return ring.getPublicKey().getUserIDs().next();
    }

    /**
     * Validate password for private key
     * @param keyId id of key to validate
     * @param pass provided password
     * @return
     */
    public static boolean validatePrivateKeyPassword(long keyId, String pass) {

        try {
            PGPSecretKeyRing ring = privateKeys.getSecretKeyRing(keyId);

            if(ring == null) {
                return false;
            }
            PGPSecretKey secret = ring.getSecretKey();
            secret.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().build(pass.toCharArray()));
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

        // if no exception was thrown it means password is correct
        return true;
    }

    /**
     * Getter for private key ring collection
     * @return
     */
    public static PGPSecretKeyRingCollection getPrivateKeyRingCollection() {
        return privateKeys;
    }

    /**
     * Getter for public key ring collection
     * @return
     */
    public static PGPPublicKeyRingCollection getPublicKeyRingCollection() {
        return publicKeys;
    }

    /**
     * Getter for error message
     * @return
     */
    public static String getCurrentError() {
        return currentError;
    }


    // End Public methods ##############################################################################################


    // Private methods #################################################################################################

    /**
     * Load private and public keyrings collections from dedicated files
     */
    private static void loadKeyRingsCollections() {

        // try to load public keys
        try {
            File publicKeyRingsFile = new File(PUBLIC_RING_PATH);
            publicKeys = new PGPPublicKeyRingCollection(new ArrayList<>());
            if(publicKeyRingsFile.exists() && !publicKeyRingsFile.isDirectory()) {
                InputStream in = new ArmoredInputStream(new FileInputStream(publicKeyRingsFile));
                publicKeys = readPublicKeyRingsFromInputStream(in);
                in.close();
            }
        } catch (Exception err) {
            err.printStackTrace();
            currentError = err.getMessage();
        }

        // try to load private keys
        try {
            File privateKeyRingsFile = new File(PRIVATE_RING_PATH);
            privateKeys = new PGPSecretKeyRingCollection(new ArrayList<>());
            if(privateKeyRingsFile.exists() && !privateKeyRingsFile.isDirectory()) {
                ArmoredInputStream in = new ArmoredInputStream(new FileInputStream(privateKeyRingsFile));
                privateKeys = readPrivateKeyRingsFromInputStream(in);
                in.close();
            }
        } catch (Exception err) {
            err.printStackTrace();
            currentError = err.getMessage();
        }

        currentError = null;
    }

    /**
     * Reads private key ring collection from armored input stream
     * @param ain ArmoredInputStream from which to read a ring
     * @return Private key ring collection on success
     * @throws PGPException PGP error
     * @throws IOException Input/Output error
     */
    private static PGPSecretKeyRingCollection readPrivateKeyRingsFromInputStream(ArmoredInputStream ain)
            throws PGPException, IOException {

        PGPSecretKeyRingCollection ret = new PGPSecretKeyRingCollection(new ArrayList<>());

        BcPGPObjectFactory inputObjects = new BcPGPObjectFactory(PGPUtil.getDecoderStream(ain));
        while(1==1) {
            Object obj = inputObjects.nextObject();
            if(obj==null) {
                break;
            }

            // throw exception when encountered something that isn't private key
            if(!(obj instanceof PGPSecretKeyRing)){
                throw new PGPException("Corrupted private key file");
            }

            ret = JcaPGPSecretKeyRingCollection.addSecretKeyRing(ret, (PGPSecretKeyRing) obj);
        }

        return ret;
    }

    /**
     * Reads public key ring collection from armored input stream
     * @param in InputStream from which to read a ring
     * @return Public key ring collection on success
     * @throws PGPException PGP error
     * @throws IOException Input/Output error
     */
    private static PGPPublicKeyRingCollection readPublicKeyRingsFromInputStream(InputStream in)
            throws PGPException, IOException {

        PGPPublicKeyRingCollection ret = new PGPPublicKeyRingCollection(new ArrayList<>());

        BcPGPObjectFactory inputObjects = new BcPGPObjectFactory(PGPUtil.getDecoderStream(in));
        while(1==1) {
            Object obj = inputObjects.nextObject();
            if(obj==null) {
                break;
            }

            // throw exception when encountered something that isn't public key
            if(!(obj instanceof PGPPublicKeyRing)){
                throw new PGPException("Corrupted public key file");
            }

            ret = JcaPGPPublicKeyRingCollection.addPublicKeyRing(ret, (PGPPublicKeyRing) obj);
        }

        return ret;
    }

    /**
     * Writes contents of private key ring collection to dedicated .asc file
     * @throws PGPException PGP error
     * @throws IOException Input/Output error
     */
    private static void persistPrivateKeyRingsCollection()
            throws PGPException, IOException {

        ArmoredOutputStream aout = new ArmoredOutputStream(new FileOutputStream(PRIVATE_RING_PATH));
        for (PGPSecretKeyRing privateKey : privateKeys) {
            privateKey.encode(aout);
        }
        aout.close();
    }

    /**
     * Writes contents of public key ring collection to dedicated .asc file
     * @throws PGPException PGP error
     * @throws IOException Input/Output error
     */
    private static void persistPublicKeyRingsCollection()
            throws PGPException, IOException {

        ArmoredOutputStream aout = new ArmoredOutputStream(new FileOutputStream(PUBLIC_RING_PATH));
        for (PGPPublicKeyRing publicKey : publicKeys) {
            publicKey.encode(aout);
        }
        aout.close();
    }

    /**
     * Adds one private or public key ring to corresponding collection
     * @param ring PGPKeyRing to add
     * @param isPublic True for public key rings, false for secret key rings
     * @throws PGPException PGP error
     * @throws IOException Input/Output error
     */
    private static void addKeyRingToCollection(PGPKeyRing ring, boolean isPublic)
            throws PGPException, IOException {

        if(isPublic) {
            if (!(ring instanceof PGPPublicKeyRing)) {
                throw new PGPException("Ring is not instance of PGPPublicKeyRing");
            }
            publicKeys = PGPPublicKeyRingCollection.addPublicKeyRing(publicKeys,(PGPPublicKeyRing) ring);
            persistPublicKeyRingsCollection();
        } else {
            if (!(ring instanceof PGPSecretKeyRing)) {
                throw new PGPException("Ring is not instance of PGPSecretKeyRing");
            }
            privateKeys = PGPSecretKeyRingCollection.addSecretKeyRing(privateKeys,(PGPSecretKeyRing) ring);
            persistPrivateKeyRingsCollection();
        }
    }

    /**
     * Reads a single private key from input stream and adds it to private key ring collection if reading successful
     * @param in input stream
     * @param isPublic True for public key rings, false for private key rings
     * @throws PGPException PGP error
     * @throws IOException Input/Output error
     */
    private static void loadSingleKeyRing(InputStream in, boolean isPublic)
            throws PGPException, IOException {

        BcPGPObjectFactory inputObjects = new BcPGPObjectFactory(PGPUtil.getDecoderStream(in));
        Object obj = inputObjects.nextObject();
        if(obj == null) {
            throw new IOException("File is empty");
        }
        if(!(obj instanceof PGPKeyRing)) {
            throw new PGPException("File does not contain a PGPKeyRing");
        }

        addKeyRingToCollection((PGPKeyRing) obj, isPublic);
    }

    /**
     * Stores a single key ring to an output stream
     * @param out Output stream
     * @param keyId Id of key to store
     * @param isPublic True for public key rings, false for private key rings
     * @throws PGPException PGP error
     * @throws IOException Input/Output error
     */
    private static void storeSingleKeyRing(OutputStream out, long keyId, boolean isPublic)
            throws PGPException, IOException {

        PGPKeyRing ring = null;
        if(isPublic) {
            ring = publicKeys.getPublicKeyRing(keyId);
        } else {
            ring = privateKeys.getSecretKeyRing(keyId);
        }
        if(ring == null) {
            throw new PGPException("Requested keyId does not belong to any KeyRing");
        }
        ring.encode(out);
    }

    /**
     * Drop single public key ring from collection
     * @param keyId Id of key to drop
     * @throws PGPException PGP error
     * @throws IOException Input/Output error
     */
    private static void dropSinglePublicKeyRing(long keyId)
            throws PGPException, IOException {

        PGPPublicKeyRing ring = publicKeys.getPublicKeyRing(keyId);
        if(ring == null) {
            throw new PGPException("Requested keyId does not belong to any PublicKeyRing");
        }
        publicKeys = PGPPublicKeyRingCollection.removePublicKeyRing(publicKeys, ring);
        persistPublicKeyRingsCollection();
    }

    /**
     * Drop single private key ring from collection
     * @param keyId Id of key to drop
     * @param passphrase Password to unlock secret key
     * @throws PGPException PGP error
     * @throws IOException Input/Output error
     */
    private static void dropSinglePrivateKeyRing(long keyId, String passphrase)
            throws PGPException, IOException {

        PGPSecretKeyRing ring = privateKeys.getSecretKeyRing(keyId);
        if(ring == null) {
            throw new PGPException("Requested keyId does not belong to any PrivateKeyRing");
        }

        PGPSecretKey secret = ring.getSecretKey();

        // checking if passed passphrase is correct
        // PGP exception will be thrown if passphrase is not correct
        try {
            secret.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().build(passphrase.toCharArray()));
        } catch (PGPException ex) {
            throw new PGPException("Invalid password");
        }

        // if no exception thrown we can remove private key ring and update collection
        privateKeys = PGPSecretKeyRingCollection.removeSecretKeyRing(privateKeys, ring);
        persistPrivateKeyRingsCollection();
    }

    /**
     * Generate new RSAKeyPair
     * @param numOfBits 1024, 2048 or 4096
     * @return Key Pair
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     */
    private static KeyPair generateRSAKeyPair(int numOfBits)
            throws NoSuchProviderException, NoSuchAlgorithmException {

        if(numOfBits != 1024 && numOfBits != 2048 && numOfBits != 4096) {
            return null;
        }

        KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
        rsaGenerator.initialize(numOfBits);
        KeyPair pair = rsaGenerator.generateKeyPair();
        return pair;
    }

    // End Private methods #############################################################################################

}
