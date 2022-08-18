package etf.openpgp.mk180034dgd180310d.gui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class MainPage extends JFrame {

    MainPage() {
        setLayout(new GridLayout(1,3));

        JButton b1 = new JButton("Key Ring Management");
        JButton b2 = new JButton("File sending");
        JButton b3 = new JButton("File receiving");

        b1.setSize(150,100);
        b2.setSize(150,100);
        b3.setSize(150,100);

        b1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                goToKeyManagement();
            }
        });

        b2.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                goToEncryption();
            }
        });

        b3.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                goToDecryption();
            }
        });

        add(b1);
        add(b2);
        add(b3);

        setResizable(false);
        setSize(600,300);
        setTitle("OpenPGP Simulation");
        setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        setVisible(true);
    }

    private void goToKeyManagement() {
        KeyRingManagement k = new KeyRingManagement();
        this.dispose();
    }

    private void goToEncryption() {
        EncryptionPage ep = new EncryptionPage();
        this.dispose();
    }

    private void goToDecryption() {
        DecryptionPage dp = new DecryptionPage();
        this.dispose();
    }

    public static void main(String args[]) {
        MainPage m1 = new MainPage();
    }

}
