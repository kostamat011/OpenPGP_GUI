package etf.openpgp.mk180034dgd180310d.gui;

import etf.openpgp.mk180034dgd180310d.key_manager.KeyData;
import etf.openpgp.mk180034dgd180310d.key_manager.KeyManager;
import etf.openpgp.mk180034dgd180310d.transfer.TransferManager;
import org.bouncycastle.openpgp.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

public class EncryptionPage extends JFrame {

    // Data ############################################################################################################
    private ArrayList<KeyData> privateKeyringsData;
    private ArrayList<KeyData> publicKeyringsData;
    private PGPSecretKeyRingCollection privateKeyrings;
    private PGPPublicKeyRingCollection publicKeyrings;

    // End Data ########################################################################################################

    // Controls ########################################################################################################

    private JPanel componentsPanel;

    private JPanel filesPanel;
    private JButton chooseFileButton;
    private JButton chooseDirButton;

    private JPanel labelsPanel;

    private JLabel chosenFileLabel;

    private JLabel chosenDirLabel;

    private JPanel encryptionPanel;
    private JCheckBox encryptCb;
    private JRadioButton tripleDesRb;
    private JRadioButton aesRb;
    private JComboBox publicKeyCombo;

    private JPanel signingPanel;

    private JCheckBox signingCb;
    private JPasswordField passwordField;
    private JComboBox privateKeyCombo;

    private JPanel radixCompressPanel;
    private JCheckBox compressCb;
    private JCheckBox radixCb;

    private JPanel startPanel;
    private JButton startButton;


    private JPanel goBackPanel;
    private JButton goBackButton;

    // End Controls ####################################################################################################

    // GUI #############################################################################################################
    public EncryptionPage() {
        loadPrivateKeyRings();
        loadPublicKeyRings();
        prepareComponentsPanel();
        add(componentsPanel);
        setWindowProperties();
        setVisible(true);
    }

    private void setWindowProperties() {
        setTitle("Encrypt/Sign Files");
        setResizable(false);
        setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        pack();
    }

    private void prepareComponentsPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        initComponents();

        panel.add(filesPanel);
        filesPanel.setAlignmentX(Component.CENTER_ALIGNMENT);
        panel.add(labelsPanel);
        panel.add(Box.createRigidArea(new Dimension(1,20)));
        panel.add(new JSeparator());

        panel.add(Box.createRigidArea(new Dimension(1,20)));
        panel.add(encryptionPanel);
        encryptionPanel.setAlignmentX(Component.CENTER_ALIGNMENT);
        panel.add(Box.createRigidArea(new Dimension(1,20)));
        panel.add(new JSeparator());

        panel.add(Box.createRigidArea(new Dimension(1,20)));
        panel.add(signingPanel);
        signingPanel.setAlignmentX(Component.CENTER_ALIGNMENT);
        panel.add(Box.createRigidArea(new Dimension(1,20)));
        panel.add(new JSeparator());

        panel.add(Box.createRigidArea(new Dimension(1,20)));
        panel.add(radixCompressPanel);
        radixCompressPanel.setAlignmentX(Component.CENTER_ALIGNMENT);
        panel.add(Box.createRigidArea(new Dimension(1,20)));
        panel.add(new JSeparator());

        panel.add(Box.createRigidArea(new Dimension(1,20)));
        panel.add(startPanel);
        startPanel.setAlignmentX(Component.CENTER_ALIGNMENT);
        panel.add(Box.createRigidArea(new Dimension(1,10)));
        panel.add(goBackPanel);
        goBackPanel.setAlignmentX(Component.CENTER_ALIGNMENT);

        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        componentsPanel = panel;
    }

    private void initComponents() {
        // choose files panel
        filesPanel = new JPanel();
        chooseFileButton = new JButton("Choose input file");
        chooseFileButton.addActionListener(chooseFileActionListener);
        chooseDirButton = new JButton("Choose output directory");
        chooseDirButton.addActionListener(chooseDirActionListener);
        filesPanel.add(chooseFileButton);
        filesPanel.add(chooseDirButton);

        // file and dir labels panel
        JPanel labelPanel1 = new JPanel();
        chosenFileLabel = new JLabel("No file chosen");
        labelPanel1.add(chosenFileLabel);

        JPanel labelPanel2 = new JPanel();
        chosenDirLabel = new JLabel("No output dir chosen");
        labelPanel2.add(chosenDirLabel);

        labelsPanel = new JPanel();
        labelsPanel.setLayout(new BoxLayout(labelsPanel, BoxLayout.Y_AXIS));
        labelsPanel.add(labelPanel1);
        labelsPanel.add(labelPanel2);

        // populate keyIds for Combo boxes
        String[] publicKeyIds = new String[publicKeyringsData.size()];
        for(int i = 0; i < publicKeyringsData.size(); ++i) {
            publicKeyIds[i] = publicKeyringsData.get(i).getKeyIdString();
        }

        String[] privateKeyIds = new String[privateKeyringsData.size()];
        for(int i = 0; i < privateKeyringsData.size(); ++i) {
            privateKeyIds[i] = privateKeyringsData.get(i).getKeyIdString();
        }

        // encryption options panel
        encryptionPanel = new JPanel();
        encryptionPanel.setLayout(new BoxLayout(encryptionPanel, BoxLayout.Y_AXIS));
        encryptCb = new JCheckBox("Encrypt");
        JLabel algorithm = new JLabel("Select encryption algorithm:");
        ButtonGroup algorithmButtons = new ButtonGroup();
        tripleDesRb = new JRadioButton("Triple DES");
        tripleDesRb.setSelected(true);
        aesRb = new JRadioButton("AES");
        algorithmButtons.add(tripleDesRb);
        algorithmButtons.add(aesRb);
        publicKeyCombo = new JComboBox<>(publicKeyIds);

        JPanel tmp1 = new JPanel();
        tmp1.add(encryptCb);

        JPanel tmp2 = new JPanel();
        tmp2.add(Box.createRigidArea(new Dimension(1,10)));
        tmp2.add(algorithm);
        tmp2.add(tripleDesRb);
        tmp2.add(aesRb);

        JPanel tmp3 = new JPanel();
        tmp3.add(new JLabel("Choose receiver public key"));
        tmp3.add(publicKeyCombo);

        encryptionPanel.add(tmp1);
        encryptionPanel.add(tmp2);
        encryptionPanel.add(tmp3);

        // signing options panel
        signingPanel = new JPanel();
        signingCb = new JCheckBox("Sign");
        signingCb.addActionListener(signingCbActionListener);
        signingPanel.setLayout(new BoxLayout(signingPanel, BoxLayout.Y_AXIS));
        passwordField = new JPasswordField(15);
        passwordField.setEnabled(false);
        privateKeyCombo = new JComboBox(privateKeyIds);

        JPanel tmp4 = new JPanel();
        tmp4.add(signingCb);

        JPanel tmp5 = new JPanel();
        tmp5.add(new JLabel("Password for unlocking private key:"));
        JPanel tmp6 = new JPanel();
        tmp6.add(passwordField);

        JPanel tmp7 = new JPanel();
        tmp7.add(new JLabel("Choose sender secret key"));
        tmp7.add(privateKeyCombo);

        signingPanel.add(tmp4);
        signingPanel.add(tmp5);
        signingPanel.add(tmp6);
        signingPanel.add(tmp7);

        // radix and compression options panel
        radixCompressPanel = new JPanel();
        radixCompressPanel.setLayout(new BoxLayout(radixCompressPanel, BoxLayout.Y_AXIS));
        compressCb = new JCheckBox("Compression");
        radixCb = new JCheckBox("Radix conversion");
        radixCompressPanel.add(compressCb);
        radixCompressPanel.add(radixCb);

        // button to start encryption
        startPanel = new JPanel();
        startButton = new JButton("Start Encrypt/Sign");
        startButton.addActionListener(startEncryptionActionListener);
        startPanel.add(startButton);

        // button to return to main menu
        goBackPanel = new JPanel();
        goBackButton = new JButton("Main menu");
        goBackButton.addActionListener(goBackActionListener);
        goBackPanel.add(goBackButton);
    }



    // End GUI #########################################################################################################

    // Actions #########################################################################################################

    private void goToMainMenu() {
        MainPage mp = new MainPage();
        this.dispose();
    }

    private void startEncryption() {
        if (chosenFileLabel.getText() == "No file chosen" || chosenDirLabel.getText() == "No output dir chosen") {
            JOptionPane.showMessageDialog(null,
                    "No file/directory selected",
                    "",
                    JOptionPane.ERROR_MESSAGE);
            return;
        }

        boolean encryption = encryptCb.isSelected();
        boolean signing = signingCb.isSelected();
        boolean radix = radixCb.isSelected();
        boolean compression = compressCb.isSelected();

        long publicKeyId = Long.parseLong(publicKeyCombo.getSelectedItem().toString(), 16);
        long secretKeyId = Long.parseLong(privateKeyCombo.getSelectedItem().toString(), 16);
        int encryptionAlgorithm = tripleDesRb.isSelected() ? PGPEncryptedData.TRIPLE_DES : PGPEncryptedData.AES_128;
        char[] password = passwordField.getPassword();

        try {
            TransferManager.sendData(chosenDirLabel.getText() + "\\encrypted.asc",
                    chosenFileLabel.getText(), secretKeyId, publicKeyId,
                    encryptionAlgorithm, radix, encryption, compression, signing, password);
            if(TransferManager.getSignatureError() == null) {
                JOptionPane.showMessageDialog(null,
                        "Successfully generated file",
                        "",
                        JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(null,
                        TransferManager.getSignatureError(),
                        "",
                        JOptionPane.ERROR_MESSAGE);
            }
        } catch (IOException e) {
            JOptionPane.showMessageDialog(null,
                    "Following error occured: "+e.getMessage(),
                    "",
                    JOptionPane.ERROR_MESSAGE);
            e.printStackTrace();
        }

    }

    private void chooseFile() {
        JFrame parent = new JFrame();
        JFileChooser fileDialog = new JFileChooser();

        // setting up file dialog
        fileDialog.setDialogTitle("Select file to encrypt/verify");
        int result = fileDialog.showOpenDialog(parent);

        if(result == JFileChooser.APPROVE_OPTION) {
            File file = fileDialog.getSelectedFile();
            chosenFileLabel.setText(file.getPath());
        }

    }

    private void chooseOutputDir() {
        JFrame parent = new JFrame();
        JFileChooser fileDialog = new JFileChooser();

        // setting up file dialog
        fileDialog.setDialogTitle("Select output directory");
        fileDialog.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        int result = fileDialog.showOpenDialog(parent);

        if(result == JFileChooser.APPROVE_OPTION) {
            File file = fileDialog.getSelectedFile();
            chosenDirLabel.setText(file.getPath());
        }
    }

    // End Actions #####################################################################################################

    // Action Listeners ################################################################################################

    ActionListener goBackActionListener = new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            goToMainMenu();
        }
    };

    ActionListener startEncryptionActionListener = new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            startEncryption();
        }
    };

    ActionListener chooseFileActionListener = new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            chooseFile();
        }
    };

    ActionListener chooseDirActionListener = new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            chooseOutputDir();
        }
    };

    ActionListener signingCbActionListener = new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            JCheckBox src = (JCheckBox) e.getSource();
            if(src.isSelected()) {
                passwordField.setEnabled(true);
            } else {
                passwordField.setEnabled(false);
            }
        }
    };

    // End Action Listeners ############################################################################################

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


}
