package etf.openpgp.mk180034dgd180310d.key_manager;

import org.bouncycastle.openpgp.PGPPublicKey;

import java.util.Date;
import java.util.Locale;

public class KeyData {
    /**
     * Id of key in hexadecimal format
     */
    private Long keyId;

    /**
     * Name of key owner
     */
    private String userName;

    /**
     * Email of key owner
     */
    private String userEmail;

    /**
     * String representation of key creation date
     */
    private String creationDate;

    /**
     * Constructor
     * @param keyId
     * @param userName
     * @param userEmail
     * @param creationDate
     */
    public KeyData(long keyId, String userName, String userEmail, Date creationDate) {
        this.keyId = keyId;
        this.userName = userName;
        this.userEmail = userEmail;
        this.creationDate = creationDate.toString();
    }

    /**
     * Constructor to extract data from key
     * @param key
     */
    public KeyData(PGPPublicKey key) {
        keyId = key.getKeyID();
        String userId = key.getUserIDs().next();
        userName = userId.substring(0, userId.indexOf("<")-1);
        userEmail = userId.substring(userId.indexOf("<")+1,userId.indexOf(">"));
        creationDate = key.getCreationTime().toString();
    }

    /**
     * Returns formated owner id from name and email
     * @return
     */
    public String getKeyOwnerId() {
        return this.userName + " <" + this.userEmail + ">";
    }

    /**
     * Returns keyId in form of hexadecimal string
     * @return
     */
    public String getKeyIdString() {
        return Long.toHexString(keyId).toUpperCase(Locale.ROOT);
    }

    // Getters and setters #############################################################################################

    public long getKeyId() {
        return keyId;
    }

    public void setKeyId(long keyId) {
        this.keyId = keyId;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getUserEmail() {
        return userEmail;
    }

    public void setUserEmail(String userEmail) {
        this.userEmail = userEmail;
    }

    public String getCreationDate() {
        return creationDate;
    }

    public void setCreationDate(String creationDate) {
        this.creationDate = creationDate;
    }

    // End Getters and setters #########################################################################################
}
