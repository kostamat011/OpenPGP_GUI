package etf.openpgp.mk180034dgd180310d.gui;

import etf.openpgp.mk180034dgd180310d.transfer.TransferManager;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.util.Locale;

public class DecryptionPage extends JFrame {

    // Controls ########################################################################################################

    private JPanel componentsPanel;

    private JPanel filesPanel;
    private JButton chooseFileButton;
    private JLabel chosenFileLabel;

    private JPanel startPanel;
    private JButton startDecryptButton;

    private JPanel chooseDirPanel;

    private JButton chooseDirButton;

    private JLabel chosenDirLabel;

    private JPanel statusPanel;
    private JTextArea statusTextArea;

    private JPanel goBackPanel;
    private JButton goBackButton;

    private String pass = "";

    private String outputDir = "";

    private boolean isEncrypted = false;

    // End Controls ####################################################################################################

    // GUI #############################################################################################################
    public DecryptionPage() {
        prepareComponentsPanel();
        add(componentsPanel);
        setWindowProperties();
        setVisible(true);
    }

    private void setWindowProperties() {
        setTitle("Decrypt/Verify Files");
        setResizable(false);
        setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        pack();
    }

    private void prepareComponentsPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        initComponents();

        panel.add(filesPanel);
        JPanel tmp1 = new JPanel();
        tmp1.add(chosenFileLabel);
        panel.add(tmp1);
        filesPanel.setAlignmentX(Component.CENTER_ALIGNMENT);
        panel.add(Box.createRigidArea(new Dimension(1, 10)));
        panel.add(chooseDirPanel);
        JPanel tmp2 = new JPanel();
        tmp2.add(chosenDirLabel);
        panel.add(tmp2);
        chooseDirPanel.setAlignmentX(Component.CENTER_ALIGNMENT);
        panel.add(Box.createRigidArea(new Dimension(1, 20)));
        panel.add(new JSeparator());

        panel.add(Box.createRigidArea(new Dimension(1, 20)));
        panel.add(startPanel);

        panel.add(Box.createRigidArea(new Dimension(1, 20)));
        panel.add(new JSeparator());

        panel.add(Box.createRigidArea(new Dimension(1, 20)));
        panel.add(statusPanel);
        panel.add(Box.createRigidArea(new Dimension(1, 20)));
        panel.add(new JSeparator());

        panel.add(goBackPanel);
        goBackPanel.setAlignmentX(Component.CENTER_ALIGNMENT);

        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        componentsPanel = panel;
    }

    private void initComponents() {
        // choose files panel
        filesPanel = new JPanel();
        chosenFileLabel = new JLabel("No file selected");
        chooseFileButton = new JButton("Choose input file");
        chooseFileButton.addActionListener(chooseFileActionListener);
        filesPanel.add(chooseFileButton);

        // choose dir panel
        chooseDirPanel = new JPanel();
        chosenDirLabel = new JLabel("No directory selected");
        chooseDirButton = new JButton("Choose output directory");
        chooseDirButton.addActionListener(chooseDirActionListener);
        chooseDirPanel.add(chooseDirButton);

        // start decrypt panel
        startPanel = new JPanel();
        startDecryptButton = new JButton("Start Decrypt/Verify");
        startDecryptButton.setEnabled(false);
        startDecryptButton.addActionListener(startDecryptionActionListener);
        startPanel.add(startDecryptButton);

        // status panel
        statusPanel = new JPanel();
        statusPanel.setLayout(new BoxLayout(statusPanel, BoxLayout.Y_AXIS));
        statusTextArea = new JTextArea(5, 30);
        statusTextArea.setEditable(false);
        JLabel tmp3 = new JLabel("Decryption/Verification status:");
        statusPanel.add(tmp3);
        statusPanel.add(statusTextArea);
        tmp3.setAlignmentX(Component.CENTER_ALIGNMENT);
        statusTextArea.setAlignmentX(Component.CENTER_ALIGNMENT);

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

    private void chooseFile() {

        JFrame parent = new JFrame();
        JFileChooser fileDialog = new JFileChooser();

        // setting up file dialog
        fileDialog.setDialogTitle("Select encrpyted/verified file");
        fileDialog.setFileFilter(new FileFilter() {
            @Override
            public boolean accept(File f) {
                if (f.isDirectory()) {
                    return true;
                } else {
                    return (f.getName().toLowerCase(Locale.ROOT).endsWith(".asc") ||
                            f.getName().toLowerCase(Locale.ROOT).endsWith(".pgp") ||
                            f.getName().toLowerCase(Locale.ROOT).endsWith(".gpg") ||
                            f.getName().toLowerCase(Locale.ROOT).endsWith(".sig"));
                }
            }

            @Override
            public String getDescription() {
                return "Supported files (*.asc, *.pgp, *.gpg, *.sig)";
            }
        });

        // get file
        int result = fileDialog.showOpenDialog(parent);

        if (result == JFileChooser.APPROVE_OPTION) {
            File file = fileDialog.getSelectedFile();

            isEncrypted = false;
            try {
                isEncrypted = TransferManager.isFileEncrypted(file);
            } catch (IOException e) {
                e.printStackTrace();
            }
            if (TransferManager.getIntegrityError() != null &&
                    TransferManager.getIntegrityError().equals("Lost message integrity.")) {
                statusTextArea.append("Lost message integrity." + "\n");
                startDecryptButton.setEnabled(false);
                return;
            }
            if (isEncrypted && !checkSecretKeyPassword()) {
                startDecryptButton.setEnabled(false);
            } else {
                startDecryptButton.setEnabled(true);
                chosenFileLabel.setText(file.getPath());
            }
        }
    }

    private boolean checkSecretKeyPassword() {
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

        // clicked Confirm - check password
        if (selectedOption == 0) {
            pass = String.valueOf(passField.getPassword());
            return true;
        }

        return false;
    }

    private void chooseDir() {
        JFrame parent = new JFrame();
        JFileChooser fileDialog = new JFileChooser();

        // setting up file dialog
        fileDialog.setDialogTitle("Select output file directory");
        fileDialog.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

        // get file
        int result = fileDialog.showOpenDialog(parent);
        if (result == JFileChooser.APPROVE_OPTION) {
            File file = fileDialog.getSelectedFile();
            chosenDirLabel.setText(file.getPath());
        }
    }

    private void startDecryption() {
        if (chosenFileLabel.getText() == "No file selected") {
            JOptionPane.showMessageDialog(null,
                    "No file/directory selected",
                    "",
                    JOptionPane.ERROR_MESSAGE);
            return;
        }
        try {
            statusTextArea.setText("");
            TransferManager.receiveData(chosenFileLabel.getText(),
                    chosenDirLabel.getText() + "/decrypted.txt",
                    pass.toCharArray());

            if (TransferManager.getIntegrityError() == null &&
                    TransferManager.getDecryptionError() == null &&
                    (TransferManager.getSignatureVerificationStatus() == null ||
                            !TransferManager.getSignatureVerificationStatus().equals("Signature verification failed."))) {
                JOptionPane.showMessageDialog(null, "Successfully received file");
            } else {
                JOptionPane.showMessageDialog(null,
                        "One or more errors in received file",
                        "",
                        JOptionPane.ERROR_MESSAGE);
            }

            if (isEncrypted) {
                String decryptionStatus = (TransferManager.getDecryptionError() == null)
                        ? "Successful decryption"
                        : TransferManager.getDecryptionError();
                statusTextArea.append(decryptionStatus + "\n");
            }

            if (TransferManager.getIntegrityError() != null) {
                statusTextArea.append(TransferManager.getIntegrityError() + "\n");
            }

            if (TransferManager.getSignatureVerificationStatus() != null) {
                statusTextArea.append(TransferManager.getSignatureVerificationStatus() + "\n");
            }

        } catch (IOException e) {
            e.printStackTrace();
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

    ActionListener startDecryptionActionListener = new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            startDecryption();
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
            chooseDir();
        }
    };

    // End Action Listeners ############################################################################################

}
