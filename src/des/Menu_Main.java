/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package des;

import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.ImageIcon;

/**
 *
 * @author azure Tran
 */
public class Menu_Main extends javax.swing.JFrame {

    /**
     * Creates new form Menu_Main
     */
     ImageIcon icon;
     String username;
    public Menu_Main(String x) {
        initComponents();
          setTitle("ĐÔ ÁN CUỐI KÌ NHÓM 3");

        icon = new ImageIcon("image/icon.jpg");
        setIconImage(icon.getImage());
        username=x;
        jLabel3.setText(x);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel6 = new javax.swing.JLabel();
        jButton1 = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        jButton5 = new javax.swing.JButton();
        jButton3 = new javax.swing.JButton();
        jLabel3 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        getContentPane().setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        jLabel6.setFont(new java.awt.Font("Tahoma", 0, 22)); // NOI18N
        jLabel6.setForeground(new java.awt.Color(255, 0, 0));
        jLabel6.setText("MÃ HOÁ VÀ GIẢI MÃ DES");
        getContentPane().add(jLabel6, new org.netbeans.lib.awtextra.AbsoluteConstraints(300, 20, 287, 28));

        jButton1.setForeground(new java.awt.Color(102, 51, 255));
        jButton1.setIcon(new javax.swing.ImageIcon("E:\\PROJECT_GROUP3\\image\\medal_champion_award_winner_olympic_icon_207807.png")); // NOI18N
        jButton1.setText("MÃ HOÁ FILE DES");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });
        getContentPane().add(jButton1, new org.netbeans.lib.awtextra.AbsoluteConstraints(500, 210, 360, -1));

        jLabel1.setFont(new java.awt.Font("Times New Roman", 0, 22)); // NOI18N
        jLabel1.setForeground(new java.awt.Color(255, 51, 51));
        jLabel1.setText("CHÀO MỪNG ");
        getContentPane().add(jLabel1, new org.netbeans.lib.awtextra.AbsoluteConstraints(188, 89, -1, -1));

        jButton5.setIcon(new javax.swing.ImageIcon("E:\\PROJECT_GROUP3\\image\\exit_closethesession_close_6317.png")); // NOI18N
        jButton5.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton5ActionPerformed(evt);
            }
        });
        getContentPane().add(jButton5, new org.netbeans.lib.awtextra.AbsoluteConstraints(815, 13, 72, 62));

        jButton3.setForeground(new java.awt.Color(255, 51, 51));
        jButton3.setIcon(new javax.swing.ImageIcon("E:\\PROJECT_GROUP3\\image\\medal_champion_award_winner_olympic_icon_207789.png")); // NOI18N
        jButton3.setText("MÃ HOÁ DES CỔ ĐIỂN");
        jButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton3ActionPerformed(evt);
            }
        });
        getContentPane().add(jButton3, new org.netbeans.lib.awtextra.AbsoluteConstraints(40, 210, 350, -1));

        jLabel3.setFont(new java.awt.Font("Times New Roman", 0, 22)); // NOI18N
        getContentPane().add(jLabel3, new org.netbeans.lib.awtextra.AbsoluteConstraints(360, 80, 90, 40));
        getContentPane().add(jLabel2, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 0, 900, 400));

        jLabel4.setIcon(new javax.swing.ImageIcon("E:\\PROJECT_GROUP3\\image\\annie-spratt-0ZPSX_mQ3xI-unsplash (1).jpg")); // NOI18N
        getContentPane().add(jLabel4, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 0, 900, 400));

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        // TODO add your handling code here:
             new DES_ENCRYPT_FILE(username).setVisible(true);
          this.dispose();
        
    }//GEN-LAST:event_jButton1ActionPerformed

    private void jButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton3ActionPerformed
        // TODO add your handling code here:
        new DES_ENCYPT(username).setVisible(true);
          this.dispose();
        
        
        
    }//GEN-LAST:event_jButton3ActionPerformed

    private void jButton5ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton5ActionPerformed
        // TODO add your handling code here:
    System.exit(0);
    }//GEN-LAST:event_jButton5ActionPerformed

    /**
     * @param args the command line arguments
     */
   
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton3;
    private javax.swing.JButton jButton5;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel6;
    // End of variables declaration//GEN-END:variables
}
