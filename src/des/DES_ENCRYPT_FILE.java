/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package des;

import static des.DES_ENCYPT.gioiHanKyTu;
import java.awt.Color;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import javafx.stage.FileChooser;
import javax.swing.JFileChooser;
import java.net.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.ImageIcon;
import javax.swing.JOptionPane;
import static javax.swing.JOptionPane.showMessageDialog;
import java.lang.*;

/**
 *
 * @author azure Tran
 */
public class DES_ENCRYPT_FILE extends javax.swing.JFrame {
            Socket client;
    DataInputStream din;
    DataOutputStream dout;
    /**
     * Creates new form GiaoDienBai2
     */
      ImageIcon icon;
      
    public DES_ENCRYPT_FILE() {
        initComponents();
         setTitle("ĐÔ ÁN CUỐI KÌ NHÓM 3");

        icon = new ImageIcon("image/icon.jpg");
        setIconImage(icon.getImage());
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
        jButton1 = new javax.swing.JButton();
        jButton2 = new javax.swing.JButton();
        jLabel4 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        content_file_des = new javax.swing.JTextField();
        txt_dir_filedes = new javax.swing.JTextField();
        jLabel6 = new javax.swing.JLabel();
        jLabel7 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        txtUppercase = new javax.swing.JTextArea();
        jLabel3 = new javax.swing.JLabel();
        txt_key = new javax.swing.JTextField();
        encypt_file = new javax.swing.JButton();
        decrypt_file = new javax.swing.JButton();
        jButton6 = new javax.swing.JButton();
        jLabel9 = new javax.swing.JLabel();
        jLabel10 = new javax.swing.JLabel();
        txt_dir_file_encrypt = new javax.swing.JTextField();
        content_file_source = new javax.swing.JTextField();
        jLabel8 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        getContentPane().setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        jLabel1.setFont(new java.awt.Font("Times New Roman", 1, 18)); // NOI18N
        jLabel1.setForeground(new java.awt.Color(255, 51, 51));
        jLabel1.setText("File encypt");
        getContentPane().add(jLabel1, new org.netbeans.lib.awtextra.AbsoluteConstraints(51, 82, 100, -1));

        jLabel2.setFont(new java.awt.Font("Times New Roman", 1, 18)); // NOI18N
        jLabel2.setForeground(new java.awt.Color(255, 51, 51));
        jLabel2.setText("File decrypt");
        getContentPane().add(jLabel2, new org.netbeans.lib.awtextra.AbsoluteConstraints(51, 323, 100, -1));

        jButton1.setText("Chọn File Mã Hoá");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });
        getContentPane().add(jButton1, new org.netbeans.lib.awtextra.AbsoluteConstraints(222, 79, -1, -1));

        jButton2.setText("Chọn File giải mã");
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });
        getContentPane().add(jButton2, new org.netbeans.lib.awtextra.AbsoluteConstraints(230, 323, -1, -1));

        jLabel4.setFont(new java.awt.Font("Times New Roman", 0, 18)); // NOI18N
        jLabel4.setText("Đường Dẫn vừa chọn:");
        getContentPane().add(jLabel4, new org.netbeans.lib.awtextra.AbsoluteConstraints(43, 122, -1, -1));

        jLabel5.setFont(new java.awt.Font("Times New Roman", 0, 18)); // NOI18N
        jLabel5.setText("Đường Dẫn vừa chọn:");
        getContentPane().add(jLabel5, new org.netbeans.lib.awtextra.AbsoluteConstraints(51, 379, -1, -1));
        getContentPane().add(content_file_des, new org.netbeans.lib.awtextra.AbsoluteConstraints(230, 420, 436, 34));
        getContentPane().add(txt_dir_filedes, new org.netbeans.lib.awtextra.AbsoluteConstraints(230, 372, 432, 39));

        jLabel6.setFont(new java.awt.Font("Tahoma", 0, 22)); // NOI18N
        jLabel6.setForeground(new java.awt.Color(255, 0, 0));
        jLabel6.setText("MÃ HOÁ VÀ GIẢI MÃ DES");
        getContentPane().add(jLabel6, new org.netbeans.lib.awtextra.AbsoluteConstraints(300, 20, 287, 28));

        jLabel7.setFont(new java.awt.Font("Times New Roman", 1, 18)); // NOI18N
        jLabel7.setForeground(new java.awt.Color(0, 153, 153));
        jLabel7.setText("DỮ LIỆU ĐƯỢC CHUYỂN THÀNH CHUỖI KÍ TỰ HOA");
        getContentPane().add(jLabel7, new org.netbeans.lib.awtextra.AbsoluteConstraints(700, 70, -1, -1));

        txtUppercase.setColumns(20);
        txtUppercase.setRows(5);
        jScrollPane1.setViewportView(txtUppercase);

        getContentPane().add(jScrollPane1, new org.netbeans.lib.awtextra.AbsoluteConstraints(690, 120, 474, 299));

        jLabel3.setFont(new java.awt.Font("Times New Roman", 1, 18)); // NOI18N
        jLabel3.setForeground(new java.awt.Color(51, 0, 255));
        jLabel3.setText("KEY");
        getContentPane().add(jLabel3, new org.netbeans.lib.awtextra.AbsoluteConstraints(51, 218, -1, -1));
        getContentPane().add(txt_key, new org.netbeans.lib.awtextra.AbsoluteConstraints(222, 213, 436, 34));

        encypt_file.setBackground(new java.awt.Color(255, 51, 51));
        encypt_file.setForeground(new java.awt.Color(240, 240, 240));
        encypt_file.setText("ENCRYPT");
        encypt_file.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                encypt_fileActionPerformed(evt);
            }
        });
        getContentPane().add(encypt_file, new org.netbeans.lib.awtextra.AbsoluteConstraints(140, 480, 110, 50));

        decrypt_file.setBackground(new java.awt.Color(255, 255, 102));
        decrypt_file.setForeground(new java.awt.Color(51, 51, 255));
        decrypt_file.setText("DECRYPT");
        getContentPane().add(decrypt_file, new org.netbeans.lib.awtextra.AbsoluteConstraints(330, 480, 90, 50));

        jButton6.setBackground(new java.awt.Color(255, 51, 255));
        jButton6.setForeground(new java.awt.Color(255, 255, 0));
        jButton6.setText("BACK");
        getContentPane().add(jButton6, new org.netbeans.lib.awtextra.AbsoluteConstraints(520, 480, 90, 50));

        jLabel9.setFont(new java.awt.Font("Times New Roman", 0, 18)); // NOI18N
        jLabel9.setText("Nội Dung File:");
        getContentPane().add(jLabel9, new org.netbeans.lib.awtextra.AbsoluteConstraints(50, 430, -1, -1));

        jLabel10.setFont(new java.awt.Font("Times New Roman", 0, 18)); // NOI18N
        jLabel10.setText("Nội Dung File:");
        getContentPane().add(jLabel10, new org.netbeans.lib.awtextra.AbsoluteConstraints(50, 170, -1, -1));
        getContentPane().add(txt_dir_file_encrypt, new org.netbeans.lib.awtextra.AbsoluteConstraints(222, 117, 436, 34));
        getContentPane().add(content_file_source, new org.netbeans.lib.awtextra.AbsoluteConstraints(220, 160, 436, 34));

        jLabel8.setIcon(new javax.swing.ImageIcon("E:\\PROJECT_GROUP3\\image\\photo-1513542789411-b6a5d4f31634.jpg")); // NOI18N
        getContentPane().add(jLabel8, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 0, 1170, 550));

        pack();
    }// </editor-fold>//GEN-END:initComponents
public String addChar(String str, char ch, int position) {
    int len = str.length();
    char[] updatedArr = new char[len + 1];
    str.getChars(0, position, updatedArr, 0);
    updatedArr[position] = ch;
    str.getChars(position, len, updatedArr, position + 1);
    return new String(updatedArr);
}
     String s1="";
    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        // TODO add your handling code here:
        JFileChooser jFileChooser = new JFileChooser();
        jFileChooser.setMultiSelectionEnabled(false);
         int x =   jFileChooser.showDialog(this, "Chọn File ");
      if   (x == JFileChooser.APPROVE_OPTION) {
      
          File f = jFileChooser.getSelectedFile();
          txt_dir_file_encrypt.setText(f.getAbsolutePath());
         
           
          
            try {
                BufferedReader bufferedReader=new BufferedReader(new FileReader(f.getAbsolutePath()));
                String s;
                while((s=bufferedReader.readLine())!=null){
           s1+=s+" ";
       }bufferedReader.close();
            } catch (FileNotFoundException ex) {
                Logger.getLogger(DES_ENCRYPT_FILE.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(DES_ENCRYPT_FILE.class.getName()).log(Level.SEVERE, null, ex);
            }
            content_file_source.setText(s1);
      }
    }//GEN-LAST:event_jButton1ActionPerformed

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        // TODO add your handling code here:
         JFileChooser jFileChooser = new JFileChooser();
         
        jFileChooser.setMultiSelectionEnabled(false);
         int x =   jFileChooser.showDialog(this, "Chọn File ");
      if   (x == JFileChooser.APPROVE_OPTION) {
      
          File f = jFileChooser.getSelectedFile();
          txt_dir_filedes.setText(f.getAbsolutePath());
          try {
                BufferedReader bufferedReader=new BufferedReader(new FileReader(f.getAbsolutePath()));
                String s;
                while((s=bufferedReader.readLine())!=null){
           s1+=s+" ";
       }bufferedReader.close();
            } catch (FileNotFoundException ex) {
                Logger.getLogger(DES_ENCRYPT_FILE.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(DES_ENCRYPT_FILE.class.getName()).log(Level.SEVERE, null, ex);
            }
            content_file_des.setText(s1);
      }
    }//GEN-LAST:event_jButton2ActionPerformed

    private void encypt_fileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_encypt_fileActionPerformed
        // TODO add your handling code here:
        if (txt_dir_file_encrypt.getText().isEmpty() ) {
            showMessageDialog(rootPane, "Vui lòng chọn file cần mã hoá ");

        }
        
       /* if (gioiHanKyTu(txt_key.getText()) == false) {
            txt_key.setText("");
            txt_key.setText("");
            JOptionPane.showMessageDialog(null, "Phải nhập đủ 8 ký tự!!!");
            return;
        }*/ else {

            try {
                // TODO add your handling code here:
          
                    client = new Socket("localhost", 8080);
                    din = new DataInputStream(client.getInputStream());
                    dout = new DataOutputStream(client.getOutputStream());
                    dout.writeInt(4);
                   
                    dout.writeUTF(txt_dir_file_encrypt.getText());
                    dout.writeUTF(txt_key.getText());
                    String encypt = din.readUTF();
                  
                    /*result_encrypt.removeAll();
                    result_decypt.setText("");
                    txtUppercase.setText("");
                    result_encrypt.setText(encypt);
                    //result_decypt.setText(decypt);
                    //resulten = decypt;
                    //txtUppercase.setText(decypt.toUpperCase());
                    
*/
                    String x=din.readUTF();
                     showMessageDialog(rootPane, x);
                 

            
                din.close();
                dout.close();
                client.close();

            } catch (IOException ex) {
                Logger.getLogger(loginFOrm.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        
    }//GEN-LAST:event_encypt_fileActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(DES_ENCRYPT_FILE.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(DES_ENCRYPT_FILE.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(DES_ENCRYPT_FILE.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(DES_ENCRYPT_FILE.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new DES_ENCRYPT_FILE().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextField content_file_des;
    private javax.swing.JTextField content_file_source;
    private javax.swing.JButton decrypt_file;
    private javax.swing.JButton encypt_file;
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButton6;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTextArea txtUppercase;
    private javax.swing.JTextField txt_dir_file_encrypt;
    private javax.swing.JTextField txt_dir_filedes;
    private javax.swing.JTextField txt_key;
    // End of variables declaration//GEN-END:variables
}
