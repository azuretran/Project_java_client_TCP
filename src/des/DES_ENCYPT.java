/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package des;

import java.awt.Color;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.text.Normalizer;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import static javax.swing.JOptionPane.showMessageDialog;

/**
 *
 * @author azure Tran
 */
public class DES_ENCYPT extends javax.swing.JFrame {

    /**
     * Creates new form NewJFrame
     */
    ImageIcon icon;
    String username;
    public DES_ENCYPT(String x) {
        initComponents();
        setTitle("ĐÔ ÁN CUỐI KÌ NHÓM 3");
        username=x;
        icon = new ImageIcon("image/icon.jpg");
        setIconImage(icon.getImage());
    }

    public static boolean gioiHanKyTu(String str) {
        if (str.length() >= 8) {
            return true;
        }
        return false;
    }
 public static boolean isBinary(String str) {
        int flag = 1;
        for (int i = 0; i < str.length(); i++) {
            if (!(str.charAt(i) == '0' || str.charAt(i) == '1')) {
                flag++;
            }
        }
        if (flag == 1) {
            return true;
        }
        return false;
    }
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        txtkey = new javax.swing.JTextField();
        txtplaintext = new javax.swing.JTextField();
        result_decypt = new javax.swing.JTextField();
        result_encrypt = new javax.swing.JTextField();
        jLabel6 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        txtUppercase = new javax.swing.JTextArea();
        bnt_decypt = new javax.swing.JButton();
        btn_back_home = new javax.swing.JButton();
        btn_encypt = new javax.swing.JButton();
        jLabel7 = new javax.swing.JLabel();
        jProgressBar1 = new javax.swing.JProgressBar();
        jLabel9 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        getContentPane().setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        jLabel1.setFont(new java.awt.Font("Tahoma", 0, 22)); // NOI18N
        jLabel1.setForeground(new java.awt.Color(255, 0, 0));
        jLabel1.setText("MÃ HOÁ VÀ GIẢI MÃ DES");
        getContentPane().add(jLabel1, new org.netbeans.lib.awtextra.AbsoluteConstraints(284, 54, 287, 28));

        jLabel2.setFont(new java.awt.Font("Times New Roman", 1, 18)); // NOI18N
        jLabel2.setForeground(new java.awt.Color(102, 0, 204));
        jLabel2.setText("PLAINTEXT");
        getContentPane().add(jLabel2, new org.netbeans.lib.awtextra.AbsoluteConstraints(12, 182, -1, -1));

        jLabel3.setFont(new java.awt.Font("Times New Roman", 1, 18)); // NOI18N
        jLabel3.setForeground(new java.awt.Color(0, 204, 51));
        jLabel3.setText("KEY");
        getContentPane().add(jLabel3, new org.netbeans.lib.awtextra.AbsoluteConstraints(12, 289, -1, -1));

        jLabel4.setFont(new java.awt.Font("Times New Roman", 1, 18)); // NOI18N
        jLabel4.setForeground(new java.awt.Color(255, 51, 0));
        jLabel4.setText("ENCRYPT");
        getContentPane().add(jLabel4, new org.netbeans.lib.awtextra.AbsoluteConstraints(12, 398, -1, -1));

        jLabel5.setFont(new java.awt.Font("Times New Roman", 1, 18)); // NOI18N
        jLabel5.setText("DECRYPT");
        getContentPane().add(jLabel5, new org.netbeans.lib.awtextra.AbsoluteConstraints(12, 473, -1, -1));
        getContentPane().add(txtkey, new org.netbeans.lib.awtextra.AbsoluteConstraints(125, 271, 289, 61));

        txtplaintext.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusGained(java.awt.event.FocusEvent evt) {
                txtplaintextFocusGained(evt);
            }
        });
        getContentPane().add(txtplaintext, new org.netbeans.lib.awtextra.AbsoluteConstraints(125, 164, 289, 61));
        getContentPane().add(result_decypt, new org.netbeans.lib.awtextra.AbsoluteConstraints(125, 456, 289, 60));

        result_encrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                result_encryptActionPerformed(evt);
            }
        });
        getContentPane().add(result_encrypt, new org.netbeans.lib.awtextra.AbsoluteConstraints(125, 376, 289, 61));

        jLabel6.setFont(new java.awt.Font("Times New Roman", 1, 18)); // NOI18N
        jLabel6.setText("DỮ LIỆU ĐƯỢC CHUYỂN THÀNH CHUỖI KÍ TỰ HOA");
        getContentPane().add(jLabel6, new org.netbeans.lib.awtextra.AbsoluteConstraints(462, 168, -1, -1));

        txtUppercase.setColumns(20);
        txtUppercase.setRows(5);
        jScrollPane1.setViewportView(txtUppercase);

        getContentPane().add(jScrollPane1, new org.netbeans.lib.awtextra.AbsoluteConstraints(462, 217, 474, 299));

        bnt_decypt.setBackground(new java.awt.Color(51, 0, 255));
        bnt_decypt.setForeground(new java.awt.Color(255, 255, 51));
        bnt_decypt.setText("DECRYPT");
        bnt_decypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                bnt_decyptActionPerformed(evt);
            }
        });
        getContentPane().add(bnt_decypt, new org.netbeans.lib.awtextra.AbsoluteConstraints(382, 630, 116, 49));

        btn_back_home.setBackground(new java.awt.Color(51, 51, 0));
        btn_back_home.setForeground(new java.awt.Color(240, 240, 240));
        btn_back_home.setText("BACK");
        btn_back_home.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_back_homeActionPerformed(evt);
            }
        });
        getContentPane().add(btn_back_home, new org.netbeans.lib.awtextra.AbsoluteConstraints(734, 630, 116, 49));

        btn_encypt.setBackground(new java.awt.Color(255, 51, 0));
        btn_encypt.setForeground(new java.awt.Color(240, 240, 240));
        btn_encypt.setText("ENCRYPT");
        btn_encypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_encyptActionPerformed(evt);
            }
        });
        getContentPane().add(btn_encypt, new org.netbeans.lib.awtextra.AbsoluteConstraints(137, 630, 116, 49));

        jLabel7.setFont(new java.awt.Font("Times New Roman", 1, 18)); // NOI18N
        jLabel7.setText("PROGRESS");
        getContentPane().add(jLabel7, new org.netbeans.lib.awtextra.AbsoluteConstraints(12, 564, -1, -1));

        jProgressBar1.setBackground(new java.awt.Color(102, 255, 102));
        getContentPane().add(jProgressBar1, new org.netbeans.lib.awtextra.AbsoluteConstraints(120, 564, 465, 22));

        jLabel9.setIcon(new javax.swing.ImageIcon("E:\\PROJECT_GROUP3\\image\\photo-1513542789411-b6a5d4f31634.jpg")); // NOI18N
        getContentPane().add(jLabel9, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, -10, 1000, 690));

        pack();
    }// </editor-fold>//GEN-END:initComponents
  Socket client;
    DataInputStream din;
    DataOutputStream dout;
    String resulten;

    private void btn_encyptActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_encyptActionPerformed
         // TODO add your handling code here:
        String s = txtkey.getText();
        s = Normalizer.normalize(s, Normalizer.Form.NFD);

        s = s.replaceAll("[\\p{InCombiningDiacriticalMarks}]", "");
        s = s.replaceAll("đ", "d");
        s = s.replaceAll("Đ", "D");
        System.out.println(s);
        if (txtkey.getText().isEmpty() || txtplaintext.getText().isEmpty()) {
            showMessageDialog(rootPane, "Vui lòng nhập đầy đủ thông tin ");

        }
        if (gioiHanKyTu(txtkey.getText()) == false) {
            txtkey.setText("");
            JOptionPane.showMessageDialog(null, "Key phải nhập đủ 8 ký tự!!!");
            return;
        }
        if (!(s.matches("[a-zA-Z_]+"))) {
            txtkey.setText("");
            JOptionPane.showMessageDialog(null, "Key không được nhập số!!!");
            return;
        } //        if(isletter(txtkey.getText()) == true){
        //            txtkey.setText("");
        //            JOptionPane.showMessageDialog(null, "Key không được nhập dấu!!!");
        //            return;
        //        }
        else {

            try {
                // TODO add your handling code here:
                try {
                    client = new Socket("localhost", 8080);
                    din = new DataInputStream(client.getInputStream());
                    dout = new DataOutputStream(client.getOutputStream());
                    dout.writeInt(2);
                    jProgressBar1.setStringPainted(true);
                    jProgressBar1.setForeground(Color.WHITE);
                    jProgressBar1.setBackground(Color.GREEN);
                    int i = 0;
                    try {
                        while (i <= 100) {
                            // fill the menu bar
                            jProgressBar1.setValue(i + 10);

                            // delay the thread
                            Thread.sleep(1000);
                            i += 20;
                        }
                    } catch (Exception e) {
                    }

                    dout.writeUTF(txtplaintext.getText());
                    dout.writeUTF(s);
                    String encypt = din.readUTF();
                    //String decypt = din.readUTF();
                    /*  this.dispose();
                    client.close();
              
                     */
                    result_encrypt.removeAll();
                    result_decypt.setText("");
                    txtUppercase.setText("");
                    result_encrypt.setText(encypt);
                    //result_decypt.setText(decypt);
                    //resulten = decypt;
                    //txtUppercase.setText(decypt.toUpperCase());

                    client.close();

                } catch (IOException ex) {
                    Logger.getLogger(loginFOrm.class.getName()).log(Level.SEVERE, null, ex);
                }

                din.close();
                dout.close();
                client.close();

            } catch (IOException ex) {
                Logger.getLogger(loginFOrm.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

    }//GEN-LAST:event_btn_encyptActionPerformed

    private void bnt_decyptActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_bnt_decyptActionPerformed
       // TODO add your handling code here:
         String s = txtkey.getText();
        s = Normalizer.normalize(s, Normalizer.Form.NFD);

        s = s.replaceAll("[\\p{InCombiningDiacriticalMarks}]", "");
        s = s.replaceAll("đ", "d");
        s = s.replaceAll("Đ", "D");
        System.out.println(s);
        if (txtkey.getText().isEmpty() || txtplaintext.getText().isEmpty()) {
            showMessageDialog(rootPane, "Vui lòng nhập đầy đủ thông tin ");
            return;
        }
        if (isBinary(txtplaintext.getText()) == false) {
            txtplaintext.setText("");
            JOptionPane.showMessageDialog(null, "Ciphertext phải là chuỗi nhị phân !!!");
            return;
        }
        if (gioiHanKyTu(txtkey.getText()) == false) {

            txtkey.setText("");
            JOptionPane.showMessageDialog(null, "Key phải nhập đủ 8 ký tự!!!");
            return;
        }

        if (!(s.matches("[a-zA-Z_]+"))) {
            txtkey.setText("");
            JOptionPane.showMessageDialog(null, "Key không được nhập số!!!");
            return;
        } else {

            try {
                // TODO add your handling code here:
                try {
                    client = new Socket("localhost", 8080);
                    din = new DataInputStream(client.getInputStream());
                    dout = new DataOutputStream(client.getOutputStream());
                    dout.writeInt(3);
                    jProgressBar1.setStringPainted(true);
                    jProgressBar1.setForeground(Color.WHITE);
                    jProgressBar1.setBackground(Color.GREEN);
                    jProgressBar1.setValue(0);
                    int i = 0;
                    try {
                        while (i <= 100) {
                            // fill the menu bar
                            jProgressBar1.setValue(i + 10);

                            // delay the thread
                            Thread.sleep(1000);
                            i += 20;
                        }
                    } catch (Exception e) {
                    }
                    result_encrypt.setText("");
                    dout.writeUTF(txtplaintext.getText());
                    dout.writeUTF(s);
                    //String encypt = din.readUTF();
                    String decypt = din.readUTF();
                    /*  this.dispose();
                    client.close();
              
                     */
                    result_decypt.removeAll();
                    result_decypt.setText(decypt);

//                    resulten = decypt;
                    txtUppercase.setText(decypt.toUpperCase());

                    client.close();

                } catch (IOException ex) {
                    Logger.getLogger(loginFOrm.class.getName()).log(Level.SEVERE, null, ex);
                }

                din.close();
                dout.close();
                client.close();

            } catch (IOException ex) {
                Logger.getLogger(loginFOrm.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

    }//GEN-LAST:event_bnt_decyptActionPerformed

    private void btn_back_homeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_back_homeActionPerformed
        // TODO add your handling code here:
        new Menu_Main(username).setVisible(true);
        this.dispose();
    }//GEN-LAST:event_btn_back_homeActionPerformed

    private void result_encryptActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_result_encryptActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_result_encryptActionPerformed

    private void txtplaintextFocusGained(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_txtplaintextFocusGained
        // TODO add your handling code here:
        txtplaintext.setText("");
         jProgressBar1.setValue(0);
    }//GEN-LAST:event_txtplaintextFocusGained

    /**
     * @param args the command line arguments
     */
   

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton bnt_decypt;
    private javax.swing.JButton btn_back_home;
    private javax.swing.JButton btn_encypt;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JProgressBar jProgressBar1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTextField result_decypt;
    private javax.swing.JTextField result_encrypt;
    private javax.swing.JTextArea txtUppercase;
    private javax.swing.JTextField txtkey;
    private javax.swing.JTextField txtplaintext;
    // End of variables declaration//GEN-END:variables
}
