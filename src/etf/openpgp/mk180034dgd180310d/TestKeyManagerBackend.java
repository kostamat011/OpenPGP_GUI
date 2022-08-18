package etf.openpgp.mk180034dgd180310d;

import etf.openpgp.mk180034dgd180310d.key_manager.KeyManager;
import org.bouncycastle.openpgp.*;

import java.io.File;

public class TestKeyManagerBackend {
    public static void main(String[] args) {
        //int s1 = generateNewKeyRingPair("kosta", "kosta@kosta.com", "degenoid", 2048, 2048);
        File f = new File("./km.asc");
        KeyManager.importKeyRing(f,true);
        // print identities of all public keys in collection
        try {
            PGPPublicKeyRingCollection pk = KeyManager.getPublicKeyRingCollection();
            for(PGPPublicKeyRing pkr : pk) {
                long id = pkr.getPublicKey().getKeyID();
                //exportKeyRing("./", id, true);
                System.out.println(id);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println(1);
    }

}
