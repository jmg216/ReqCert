/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * ResponseApplet.java
 *
 * Created on 16/02/2011, 09:32:00 AM
 */

package Applet;

import Applet.utiles.Utiles;
import Applet.utiles.UtilesTrustedX;
import com.isa.SW.exceptions.SWException;
import com.isa.SW.utils.UtilesResources;
import com.isa.SW.utils.UtilesSWHelper;
import java.awt.Cursor;
import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import netscape.javascript.JSObject;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author ISA
 */
public class InstallCertApplet extends javax.swing.JApplet {
    
    private static final boolean IS_PRUEBA = false;
    private String artifact;

    /** Initializes the applet ResponseApplet */
    @Override
    public void init() {
        try {
            if (IS_PRUEBA){
                UtilesSWHelper.setCodeBase(new URL("http://dom01test.imm.gub.uy/Solicitud/"));
                UtilesTrustedX.setIsTrustedX(true);
                initComponents();
                Utiles.addProvider();                           
            }
            else{
                UtilesSWHelper.setCodeBase(getCodeBase());
                UtilesTrustedX.setIsTrustedX(getParameter(UtilesTrustedX.TRUSTED_PARAM).equals(UtilesTrustedX.TRUSTED_VALUE));
                initComponents();
                Utiles.addProvider();           
            }
            initButton();

        } catch (Exception ex) {
            Logger.getLogger(InstallCertApplet.class.getName()).log(Level.SEVERE, null, ex);
            desplegarError();
        }

    }
    
    public void initButton(){
        jButton1.setCursor(new Cursor(Cursor.HAND_CURSOR));
        jButton1.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                jButton1.setBackground( Utiles.getColorHoverButton() );
            }

            @Override
            public void mouseExited(java.awt.event.MouseEvent evt) {
                jButton1.setBackground( Utiles.getInitColorButton() );
            }
        });          
    }
    
    private void abrirBloqueoModal(){
        JSObject win = (JSObject) JSObject.getWindow(this);
        win.eval("abrirProcesandoApplet()"); 
    }

    private void cerrarBloqueModal(){
        JSObject win = (JSObject) JSObject.getWindow(this);
        win.eval("cerrarProcesandoApplet()");            
    }
    
    private void desplegarError() {
        JSObject win = (JSObject) JSObject.getWindow(this);
        win.eval("desplegarError()");
    }
    
    private void desplegarMsj(String str) {
        JSObject win = (JSObject) JSObject.getWindow(this);
        win.eval("desplegarMsj(\""+ str +"\")");
    }

    private String getCertCABase64() {
        JSObject win = (JSObject) JSObject.getWindow(this);
        return (String) win.eval("getCertCABase64()");
    }
    
    private String getPassword(){
        JSObject win = (JSObject) JSObject.getWindow(this);
        return (String) win.eval("getPassword()");        
    }

    private String getCertBase64() {
        JSObject win = (JSObject) JSObject.getWindow(this);
        return (String) win.eval("getCertBase64()");
    }
    
    private String obtenerUsuario(){
        return getParameter("usuario");
    }

    private boolean validarPasswordEmpty(){
        return !Utiles.isNullOrEmpty(getPassword());
    }
        
    
    private void instalarCertificadoTrustedX() throws SWException, CertificateException, NoSuchAlgorithmException, IOException{
        try{
            String usuario = obtenerUsuario();
            String password = Utiles.convertToSHA256(getPassword());
            
            long startTime = System.currentTimeMillis();
            
            artifact = null;
            artifact = UtilesTrustedX.login(usuario, password);
            
            UtilesTrustedX.instalarCertificado(artifact, getCertCABase64(),
                    getCertBase64(), 
                        Utiles.getDN(usuario, UtilesResources.getProperty("swHelperConfig.trustedOU")));
            
            UtilesTrustedX.logout(usuario, artifact);
            
            long endTime = System.currentTimeMillis();
            long timeResult = (endTime - startTime);          
            System.out.println("TIEMPO TOTAL INSERTAR CERTIFICADO: " + (Utiles.convertTimeMillisToSeconds(timeResult)) + " SEGUNDOS");
        }
        catch( SWException e ){
            if (artifact != null){
                UtilesTrustedX.logout(obtenerUsuario(), artifact);
            }
            throw e;
        }
    }    


    /** This method is called from within the init() method to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel1 = new javax.swing.JPanel();
        jButton1 = new javax.swing.JButton();

        getContentPane().setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        jPanel1.setBackground(new java.awt.Color(255, 255, 255));
        jPanel1.setPreferredSize(new java.awt.Dimension(200, 200));
        jPanel1.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 0, 0));

        jButton1.setBackground(new java.awt.Color(57, 155, 255));
        jButton1.setFont(new java.awt.Font("SansSerif", 1, 12)); // NOI18N
        jButton1.setForeground(new java.awt.Color(255, 255, 255));
        jButton1.setText("Instalar Certificado");
        jButton1.setBorder(new javax.swing.border.LineBorder(new java.awt.Color(57, 155, 255), 5, true));
        jButton1.setBorderPainted(false);
        jButton1.setPreferredSize(new java.awt.Dimension(255, 30));
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });
        jPanel1.add(jButton1);

        getContentPane().add(jPanel1, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 0, 310, 110));
    }// </editor-fold>//GEN-END:initComponents

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed

        if (UtilesTrustedX.isTrustedX()){
            try{
                if (validarPasswordEmpty()){
                    abrirBloqueoModal();
                    instalarCertificadoTrustedX();
                    cerrarBloqueModal();
                    desplegarMsj("Su certificado se instaló correctamente en TrustedX.");
                }
                else{
                    desplegarMsj("El campo Contraseña de firma es obligatorio.");
                }

            } catch (SWException ex) {
                cerrarBloqueModal();
                System.out.println("Tipo: " + ex.getTipo());
                System.out.println("Mensaje: " + ex.getMensaje());
                Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
                if (SWException.ERROR_DE_AUTENTICACION.equals(ex.getTipo())){
                    desplegarMsj("La contraseña que ingresó es incorrecta. Intente nuevamente.");
                }
                else{
                    desplegarMsj(ex.getMensaje());
                }
            } catch (IOException ex) {
                cerrarBloqueModal();
                Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
                System.out.println("Class: " + ex.getClass().getName());
                System.out.println("Mensaje: " + ex.getMessage());            
                desplegarError();
            } catch (CertificateException ex) {
                cerrarBloqueModal();
                System.out.println("Class: " + ex.getClass().getName());
                System.out.println("Mensaje: " + ex.getMessage());            
                Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
                desplegarError();
            } catch (NoSuchAlgorithmException ex) {
                cerrarBloqueModal();
                System.out.println("Class: " + ex.getClass().getName());
                System.out.println("Mensaje: " + ex.getMessage());            
                Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
                desplegarError();
            } catch (Exception ex){
                cerrarBloqueModal();
                System.out.println("Class: " + ex.getClass().getName());
                System.out.println("Mensaje: " + ex.getMessage());            
                Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
                desplegarError();            
            } 
        }
    }//GEN-LAST:event_jButton1ActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton1;
    private javax.swing.JPanel jPanel1;
    // End of variables declaration//GEN-END:variables

}
