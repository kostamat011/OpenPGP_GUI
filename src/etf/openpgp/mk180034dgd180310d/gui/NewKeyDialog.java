package etf.openpgp.mk180034dgd180310d.gui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class NewKeyDialog extends JDialog implements ActionListener {
    // Parent
    KeyRingManagement parent;

    // Components ######################################################################################################

    private JTextField userNameField;
    private JTextField emailField;
    private JPasswordField passphraseField;
    private JComboBox encryptSelect;
    private JComboBox signSelect;

    private JButton confirmButton;

    private JPanel contentPanel;

    // End Components ##################################################################################################

    // Data ############################################################################################################

    private static final String[] keySizeOptions = {"1024", "2048", "4096"};
    private String[] returnData = new String[5];

    // End Data ########################################################################################################

    public NewKeyDialog(KeyRingManagement caller) {
        super(caller,"Enter new key data", false);
        setWindowProperties();
        prepareContentPanel();
        add(contentPanel);
        contentPanel.setAlignmentX(Component.CENTER_ALIGNMENT);
        setModal(true);
        pack();
    }

    private void prepareContentPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(6,2, 20, 10));

        initComponents();

        JLabel name = new JLabel("User name");
        name.setHorizontalAlignment(JLabel.CENTER);
        panel.add(name);
        panel.add(userNameField);
        //panel.add(Box.createRigidArea(new Dimension(1,10)));

        JLabel email = new JLabel("User email");
        email.setHorizontalAlignment(JLabel.CENTER);
        panel.add(email);
        panel.add(emailField);
        //panel.add(Box.createRigidArea(new Dimension(1,10)));

        JLabel pass = new JLabel("Passphrase");
        pass.setHorizontalAlignment(JLabel.CENTER);
        panel.add(pass);
        panel.add(passphraseField);
        //panel.add(Box.createRigidArea(new Dimension(1,10)));

        panel.add(new JLabel("RSA Encryption Key size"));
        panel.add(encryptSelect);
        //panel.add(Box.createRigidArea(new Dimension(1,10)));

        panel.add(new JLabel("RSA Signing Key size"));
        panel.add(signSelect);

        contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
        contentPanel.add(panel);
        contentPanel.add(confirmButton);
        contentPanel.add(Box.createRigidArea(new Dimension(1,10)));
        confirmButton.setAlignmentX(Component.CENTER_ALIGNMENT);
    }

    private void setWindowProperties() {
        setTitle("New Keypair data");
        setResizable(false);
        setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
    }

    private void initComponents() {

        userNameField = new JTextField();

        emailField = new JTextField();

        passphraseField = new JPasswordField();

        encryptSelect = new JComboBox(keySizeOptions);

        signSelect = new JComboBox(keySizeOptions);

        confirmButton = new JButton("Confirm");

        confirmButton.addActionListener(this);
    }

    public void actionPerformed(ActionEvent e) {
        Object source = e.getSource();
        if(source == confirmButton) {
            returnData[0] = userNameField.getText();
            returnData[1] = emailField.getText();
            returnData[2] = String.valueOf(passphraseField.getPassword());
            returnData[3] = (String)encryptSelect.getSelectedItem();
            returnData[4] = (String)signSelect.getSelectedItem();
        }
        dispose();
    }

    public String[] run() {
        this.setVisible(true);
        return returnData;
    }
}
