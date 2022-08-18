package etf.openpgp.mk180034dgd180310d.gui;

import etf.openpgp.mk180034dgd180310d.key_manager.KeyData;
import etf.openpgp.mk180034dgd180310d.key_manager.KeyManager;
import org.bouncycastle.openpgp.*;

import javax.swing.*;
import javax.swing.filechooser.FileFilter;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.ArrayList;
import java.util.Locale;

public class KeyRingManagement extends JFrame {

    // Data ############################################################################################################
    private ArrayList<KeyData> privateKeyringsData;
    private ArrayList<KeyData> publicKeyringsData;
    private PGPSecretKeyRingCollection privateKeyrings;
    private PGPPublicKeyRingCollection publicKeyrings;
    private static final String[] columns = {"Username", "Email", "Key ID", "Creation time"};

    // End Data ########################################################################################################

    // Controls ########################################################################################################

    private JScrollPane privateKeyringsScrollPane;

    private JScrollPane publicKeyringsScrollPane;

    private JTable privateKeyringsTable;

    private DefaultTableModel publicKeyringsTableModel;

    private JTable publicKeyringsTable;

    private DefaultTableModel privateKeyringsTableModel;

    private JPanel componentsPanel;

    private JPanel privateControlsPanel;
    private JButton privateExportButton;
    private JButton privateImportButton;
    private JButton privateDeleteButton;

    private JPanel publicControlsPanel;
    private JButton publicExportButton;
    private JButton publicImportButton;
    private JButton publicDeleteButton;

    private JPanel generateNewPanel;
    private JButton generateNewButton;

    private JPanel goBackPanel;
    private JButton goBackButton;

    private JLabel currentError;

    // End Controls ####################################################################################################

    public KeyRingManagement() {
        loadPrivateKeyRings();
        loadPublicKeyRings();
        setWindowProperties();
        prepareComponentsPanel();
        add(componentsPanel);
        setVisible(true);
    }

    // GUI Setup #######################################################################################################
    private void setWindowProperties() {
        setTitle("Key ring management");
        setSize(800, 600);
        setResizable(false);
        setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
    }

    private void prepareComponentsPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        initComponents();

        panel.add(Box.createRigidArea(new Dimension(1,20)));
        panel.add( new JLabel("Public Key Rings"));
        panel.add( publicKeyringsScrollPane);
        panel.add( publicControlsPanel);
        panel.add(Box.createRigidArea(new Dimension(1,50)));
        panel.add( new JLabel("Private Key Rings"));
        panel.add( privateKeyringsScrollPane);
        panel.add( privateControlsPanel);
        panel.add(Box.createRigidArea(new Dimension(1,50)));
        panel.add(generateNewButton);
        panel.add(Box.createRigidArea(new Dimension(1,10)));
        panel.add(goBackButton);
        goBackButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        generateNewButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        panel.add(Box.createRigidArea(new Dimension(1,20)));

        JPanel errorPanel = new JPanel();
        errorPanel.add(currentError);
        panel.add(errorPanel);
        panel.add(Box.createRigidArea(new Dimension(1,20)));

        componentsPanel = panel;
    }

    private void initComponents() {

        // init public keyring table
        publicKeyringsTableModel = new DefaultTableModel(columns,0);
        populatePublicKeyringsTableModel();
        publicKeyringsTable = new JTable(publicKeyringsTableModel);
        publicKeyringsScrollPane = new JScrollPane(publicKeyringsTable);

        // init private keyring table
        privateKeyringsTableModel = new DefaultTableModel(columns,0);
        populatePrivateKeyringsTableModel();
        privateKeyringsTable = new JTable(privateKeyringsTableModel);
        privateKeyringsScrollPane = new JScrollPane(privateKeyringsTable);

        // init private keyring controls
        privateControlsPanel = new JPanel();
        privateControlsPanel.setLayout(new BoxLayout(privateControlsPanel, BoxLayout.X_AXIS));

        privateImportButton = new JButton("Import");
        privateImportButton.addActionListener(privateImportActionListener);

        privateExportButton = new JButton("Export");
        privateExportButton.addActionListener(privateExportActionListener);

        privateDeleteButton = new JButton("Delete");
        privateDeleteButton.addActionListener(privateDeleteActionListener);

        privateControlsPanel.add(privateImportButton);
        privateControlsPanel.add(privateExportButton);
        privateControlsPanel.add(privateDeleteButton);

        // init public keyring controls
        publicControlsPanel = new JPanel();
        publicControlsPanel.setLayout(new BoxLayout(publicControlsPanel, BoxLayout.X_AXIS));

        publicImportButton = new JButton("Import");
        publicImportButton.addActionListener(publicImportActionListener);

        publicExportButton = new JButton("Export");
        publicExportButton.addActionListener(publicExportActionListener);

        publicDeleteButton = new JButton("Delete");
        publicDeleteButton.addActionListener(publicDeleteActionListener);

        publicControlsPanel.add(publicImportButton);
        publicControlsPanel.add(publicExportButton);
        publicControlsPanel.add(publicDeleteButton);

        // init other buttons
        generateNewButton = new JButton("Generate new KeyPair");
        generateNewButton.addActionListener(generateKeysActionListener);
        goBackButton = new JButton("Main Menu");
        goBackButton.addActionListener(mainMenuActionListener);

        // init error text
        currentError = new JLabel();
        currentError.setForeground(Color.RED);
        currentError.setText("");
    }

    private void populatePublicKeyringsTableModel() {
        for(KeyData kd : publicKeyringsData) {
            String[] cells = {kd.getUserName(), kd.getUserEmail(), kd.getKeyIdString(), kd.getCreationDate() };
            publicKeyringsTableModel.addRow(cells);
        }
    }

    private void clearPublicKeyringsTableModel() {
        int cnt = publicKeyringsTableModel.getRowCount();
        for(int i=0; i<cnt; ++i) {
            publicKeyringsTableModel.removeRow(0);
        }
    }

    private void populatePrivateKeyringsTableModel() {
        for(KeyData kd : privateKeyringsData) {
            String[] cells = {kd.getUserName(), kd.getUserEmail(), kd.getKeyIdString(), kd.getCreationDate() };
            privateKeyringsTableModel.addRow(cells);
        }
    }

    private void clearPrivateKeyringsTableModel() {
        int cnt = privateKeyringsTableModel.getRowCount();
        for(int i=0; i<cnt; ++i) {
            privateKeyringsTableModel.removeRow(0);
        }
    }

    private void resetError() {
        if(KeyManager.getCurrentError() == null) {
            currentError.setText("");
        } else {
            currentError.setText(KeyManager.getCurrentError());
        }
        currentError.revalidate();
        currentError.repaint();
    }

    // End GUI Setup ###################################################################################################

    // Action Listeners ################################################################################################

    ActionListener privateExportActionListener = new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            long keyId = getSelectedPrivateKey();
            exportKeyring(keyId, false);
        }
    };

    ActionListener privateImportActionListener = new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            importKeyring(false);
        }
    };

    ActionListener privateDeleteActionListener = new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            removeKeyring(getSelectedPrivateKey(), false);
        }
    };

    ActionListener publicExportActionListener = new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            long keyId = getSelectedPublicKey();
            exportKeyring(keyId, true);
        }
    };

    ActionListener publicImportActionListener = new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            importKeyring(true);
        }
    };

    ActionListener publicDeleteActionListener = new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            removeKeyring(getSelectedPublicKey(), true);
        }
    };

    ActionListener generateKeysActionListener = new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            generateNewKeyPair();
        }
    };

    ActionListener mainMenuActionListener = new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            goToMainMenu();
        }
    };

    // End Action Listeners ############################################################################################

    // Actions #########################################################################################################
    private void loadPublicKeyRings() {
        publicKeyringsData = new ArrayList<>();
        publicKeyrings = KeyManager.getPublicKeyRingCollection();
        for(PGPPublicKeyRing ring : publicKeyrings) {
            PGPPublicKey masterKey = ring.getPublicKey();
            KeyData keyData = new KeyData(masterKey);
            publicKeyringsData.add(keyData);
        }
    }

    private void loadPrivateKeyRings() {
        privateKeyringsData = new ArrayList<>();
        privateKeyrings = KeyManager.getPrivateKeyRingCollection();
        for(PGPSecretKeyRing ring : privateKeyrings) {
            PGPPublicKey masterKey = ring.getPublicKey();
            KeyData keyData = new KeyData(masterKey);
            privateKeyringsData.add(keyData);
        }
    }

    private void exportKeyring(long keyId, boolean isPublic) {
        JFrame parent = new JFrame();
        JFileChooser fileDialog = new JFileChooser();

        fileDialog.setDialogTitle("Select a folder to export your key");
        fileDialog.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

        int result = fileDialog.showSaveDialog(parent);

        if(result == JFileChooser.APPROVE_OPTION) {
            File file = fileDialog.getSelectedFile();
            KeyManager.exportKeyRing(file.getPath(),keyId,isPublic);
        }

        resetError();
    }

    private void importKeyring(boolean isPublic) {
        JFrame parent = new JFrame();
        JFileChooser fileDialog = new JFileChooser();

        fileDialog.setDialogTitle("Select a KeyringFile");
        fileDialog.setFileFilter(new FileFilter() {
            @Override
            public boolean accept(File f) {
                if(f.isDirectory()) {
                    return true;
                } else {
                    return ( f.getName().toLowerCase(Locale.ROOT).endsWith(".asc") ||
                             f.getName().toLowerCase(Locale.ROOT).endsWith(".pgp"));
                }
            }

            @Override
            public String getDescription() {
                return "Supported Keyring files (*.asc, *.pgp)";
            }
        });

        int result = fileDialog.showOpenDialog(parent);

        if(result == JFileChooser.APPROVE_OPTION) {
            File file = fileDialog.getSelectedFile();
            KeyManager.importKeyRing(file,isPublic);
            if(isPublic) {
                reloadPublicTable();
            } else {
                reloadPrivateTable();
            }
        }
        resetError();
    }

    private void removeKeyring(long keyId, boolean isPublic) {
        // public key - just delete
        if(isPublic) {
            KeyManager.deleteKeyRing(keyId,true,"");
            reloadPublicTable();
        }

        // private key - ask for a password
        else {
            // prepare password dialog
            JPanel passPanel = new JPanel();
            JLabel passLabel = new JLabel("Password?");
            JPasswordField passField = new JPasswordField(20);
            passPanel.add(passLabel);
            passPanel.add(passField);
            String[] options = new String[]{"Confirm", "Abort"};

            int selectedOption = JOptionPane.showOptionDialog(
                    null,
                    passPanel,
                    "Enter the password for secret key:",
                    JOptionPane.NO_OPTION,
                    JOptionPane.PLAIN_MESSAGE,
                    null,
                    options,
                    options[1]);

            // clicked Confirm
            if(selectedOption == 0) {
                String pass = String.valueOf(passField.getPassword());
                KeyManager.deleteKeyRing(keyId,false,pass);
                reloadPrivateTable();
            }
        }
        resetError();
    }

    private void generateNewKeyPair() {
        NewKeyDialog dialog = new NewKeyDialog(this);
        String[] keyData = dialog.run();
        if(keyData[0] == null) {
            return;
        }
        String userName = keyData[0];
        String userEmail = keyData[1];
        String passphrase = keyData[2];
        int rsaEncryptionKeySize = Integer.parseInt(keyData[3]);
        int rsaSigningKeySize = Integer.parseInt(keyData[4]);
        KeyManager.generateNewKeyRingPair(userName,userEmail,passphrase,rsaEncryptionKeySize,rsaSigningKeySize);

        reloadPublicTable();
        reloadPrivateTable();
        resetError();
    }

    private void goToMainMenu() {
        MainPage mp = new MainPage();
        this.dispose();
    }

    // End Actions #####################################################################################################

    // Util ############################################################################################################

    private void reloadPrivateTable() {
        loadPrivateKeyRings();
        clearPrivateKeyringsTableModel();
        populatePrivateKeyringsTableModel();
        resetError();
    }

    private void reloadPublicTable() {
        loadPublicKeyRings();
        clearPublicKeyringsTableModel();
        populatePublicKeyringsTableModel();
        resetError();
    }

    private long getSelectedPrivateKey() {
        int selectedKey = privateKeyringsTable.getSelectedRow();
        String keyId = privateKeyringsTable.getValueAt(selectedKey, 2).toString();
        long keyIdLong = Long.parseUnsignedLong(keyId, 16);
        return keyIdLong;
    }

    private long getSelectedPublicKey() {
        int selectedKey = publicKeyringsTable.getSelectedRow();
        String keyId = publicKeyringsTable.getValueAt(selectedKey, 2).toString();
        long keyIdLong = Long.parseUnsignedLong(keyId, 16);
        return keyIdLong;
    }

    // End Util ########################################################################################################
}
