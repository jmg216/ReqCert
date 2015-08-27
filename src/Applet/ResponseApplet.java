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
public class ResponseApplet extends javax.swing.JApplet {
    private KeyStore keysLocal;
    private X509Certificate certFirmado;
    private String alias;
    private String keystoreAct;
    private X509Certificate certCA;
    private String artifact;
    private static final String MSJ_ESPERA= "Espere un momento mientras se instala el certificado...";
    private static final boolean IS_PRUEBA = false;

    /** Initializes the applet ResponseApplet */
    @Override
    public void init() {
        try {
            if (IS_PRUEBA){
                UtilesSWHelper.setCodeBase(new URL("http://dom01test.imm.gub.uy/Solicitud/"));
                UtilesTrustedX.setIsTrustedX(true);
                keystoreAct = "1";
                initComponents();
                Utiles.addProvider();
                mostrarSoloInstalar();
                descargar2.setVisible(true);
                descargar3.setVisible(true);                               
            }
            else{
                UtilesSWHelper.setCodeBase(getCodeBase());
                UtilesTrustedX.setIsTrustedX(getParameter(UtilesTrustedX.TRUSTED_PARAM).equals(UtilesTrustedX.TRUSTED_VALUE));
                keystoreAct = getParameter("keystore"); //"1"
                initComponents();
                Utiles.addProvider();
                mostrarSoloInstalar();
                descargar2.setVisible(keystoreAct.equals("1"));
                descargar3.setVisible(keystoreAct.equals("1"));               
            }
        } catch (Exception ex) {
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            desplegarError();
            this.mostrarSoloInstalar();
        }

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
    
    private void desplegarErrorStr(String str) {
        JSObject win = (JSObject) JSObject.getWindow(this);
        win.eval("desplegarErrorStr(\""+ str +"\")");
    }

    private void desplegarErrorNoExiste() {
        JSObject win = (JSObject) JSObject.getWindow(this);
        win.eval("desplegarErrorNoExiste()");
    }

    private String getCertCABase64() {
        JSObject win = (JSObject) JSObject.getWindow(this);
        return (String) win.eval("getCertCABase64()");
    }
    
    private void mostrarSoloInstalar(){
        this.instalarCertificado.setEnabled(true);
        this.panelInstalar.setVisible(true);
        this.jPanel2.setVisible(false);
        this.jPanel4.setVisible(false);
        this.jPanel3.setVisible(false);
        this.jPanel5.setVisible(false);
    }

    private void mostrarContraseña(){
        this.campoPass.setText("");
        this.instalarCertificado.setEnabled(false);
        this.jPanel2.setVisible(true);
        this.jPanel4.setVisible(false);
        this.jPanel3.setVisible(false);
        this.jPanel5.setVisible(false);
        
    }

    private void mostrarContraseñaError(){
        jLabel6.setText( "La contraseña que ingresó es incorrecta. Intente nuevamente." );
        this.campoPass1.setText("");
        this.instalarCertificado.setEnabled(false);
        this.jPanel2.setVisible(false);
        this.jPanel4.setVisible(false);
        this.jPanel3.setVisible(true);
        this.jPanel5.setVisible(false);
    }
    
    private void mostrarFinalizada2(){
        this.instalarCertificado.setEnabled(false);
        this.jPanel2.setVisible(false);
        this.jPanel4.setVisible(false);
        this.jPanel3.setVisible(false);
        this.jPanel5.setVisible(true);
    }

    private String getCertBase64() {
        JSObject win = (JSObject) JSObject.getWindow(this);
        return (String) win.eval("getCertBase64()");
    }
    
    private String obtenerUsuario(){
        return getParameter("usuario").toUpperCase();
    }
    
    /**
     Método que verifica si el certificado pedido por el usuario sea el correcto.
     */
    private boolean verificarCertificadoLocal( ) throws CertificateException, KeyStoreException, IOException, FileNotFoundException, NoSuchAlgorithmException, NoSuchProviderException{
        
        String certBase64 = getCertBase64();
        String certCABase64 = getCertCABase64();
        String nombreUsuario = obtenerUsuario();
            
        certFirmado = Utiles.decodeCertificate(certBase64);
        certCA = Utiles.decodeCertificate(certCABase64);
        keysLocal = Utiles.obtenerKeyStore();
        alias = null;
            
        boolean encontre = false;
        Certificate c;
        Enumeration enumer = keysLocal.aliases();
        
        while ( enumer.hasMoreElements() && !encontre ) {
            alias = (String) enumer.nextElement();
            c = (Certificate) keysLocal.getCertificate(alias);
            X509Certificate x509cert = (X509Certificate) c;
            encontre = x509cert.getPublicKey().equals(certFirmado.getPublicKey());
            encontre = encontre && Utiles.getCN(x509cert.getSubjectDN().getName()).equals(nombreUsuario);
        }
        return encontre;
    }    
    
    private void instalarCertificadoTrustedX() throws SWException, CertificateException, NoSuchAlgorithmException, IOException{
        
        try{
            String usuario = obtenerUsuario();
            String password = new String ( campoPass.getPassword() );
            
            long startTime = System.currentTimeMillis();
            
            artifact = null;
            artifact = UtilesTrustedX.login(usuario, password);
            System.out.println("Artifact: " + artifact);
            UtilesTrustedX.instalarCertificado(artifact, getCertCABase64(),
                    getCertBase64(), 
                        Utiles.getDN(usuario, UtilesResources.getProperty("swHelperConfig.trustedOU")));
            
            UtilesTrustedX.logout(usuario, artifact);
            
            long endTime = System.currentTimeMillis();
            long timeResult = (endTime - startTime);          
            System.out.println("TIEMPO TOTAL INSERTAR CERTIFICADO: " + (Utiles.convertTimeMillisToSeconds(timeResult)) + " SEGUNDOS");            
        }
        catch(SWException e){
            if (artifact != null){
                UtilesTrustedX.logout(obtenerUsuario(), artifact);
            }
            throw e;
        }
    }    

    private boolean guardarCertificado(PrivateKey privada, X509Certificate certFirmado, X509Certificate certCA,char[] pass) throws KeyStoreException, NoSuchProviderException, IOException, NoSuchAlgorithmException, CertificateException {
        JFileChooser chooser = new JFileChooser();
        int status = chooser.showSaveDialog(jPanel1);
        if(status == JFileChooser.APPROVE_OPTION){
            File saveFile = chooser.getSelectedFile();
            String savePath = saveFile.getAbsolutePath();
            if (savePath.endsWith(".pfx")){
                savePath = savePath.replace(".pfx","");
            }
            if (!(new File(savePath+".pfx").exists())){
                KeyStore keyS = KeyStore.getInstance("PKCS12");
                keyS.load(null,null);
                //keyS.setCertificateEntry(certFirmado.getSerialNumber().toString(), certFirmado);
                keyS.setKeyEntry(certFirmado.getSerialNumber().toString(), privada, pass, new X509Certificate[]{certFirmado,certCA});
                FileOutputStream out = new FileOutputStream(savePath+".pfx");
                keyS.store(out, pass);
                out.close();
                return true;
            }else{
                int answer = JOptionPane.showConfirmDialog(jPanel1, "Ya existe un archivo con ese nombre. ¿Desea reemplazarlo?","Descarga",JOptionPane.YES_NO_OPTION);
                if (answer == JOptionPane.YES_OPTION) {
                    KeyStore keyS = KeyStore.getInstance("PKCS12");
                    keyS.load(null,null);
                    //keyS.setCertificateEntry(certFirmado.getSerialNumber().toString(), certFirmado);
                    keyS.setKeyEntry(certFirmado.getSerialNumber().toString(), privada, pass, new Certificate[]{certFirmado,certCA});
                    FileOutputStream out = new FileOutputStream(savePath+".pfx");
                    keyS.store(out, pass);
                    out.close();
                    return true;
                } else if (answer == JOptionPane.NO_OPTION) {
                  return false;
                }

            }
        }
        return false;
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
        panelInstalar = new javax.swing.JPanel();
        instalarCertificado = new javax.swing.JButton();
        jPanel3 = new javax.swing.JPanel();
        panelContraseñaError = new javax.swing.JPanel();
        jLabel5 = new javax.swing.JLabel();
        campoPass1 = new javax.swing.JPasswordField();
        jLabel6 = new javax.swing.JLabel();
        descargar1 = new javax.swing.JButton();
        descargar2 = new javax.swing.JButton();
        jPanel2 = new javax.swing.JPanel();
        panelContraseña = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        campoPass = new javax.swing.JPasswordField();
        jLabel2 = new javax.swing.JLabel();
        descargar = new javax.swing.JButton();
        descargar3 = new javax.swing.JButton();
        jPanel4 = new javax.swing.JPanel();
        panelFinalizada = new javax.swing.JPanel();
        jLabel4 = new javax.swing.JLabel();
        jPanel5 = new javax.swing.JPanel();
        panelFinalizada1 = new javax.swing.JPanel();
        jLabel7 = new javax.swing.JLabel();

        getContentPane().setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.CENTER, 0, 0));

        jPanel1.setBackground(new java.awt.Color(255, 255, 255));
        jPanel1.setMaximumSize(new java.awt.Dimension(400, 165));
        jPanel1.setMinimumSize(new java.awt.Dimension(400, 165));
        jPanel1.setPreferredSize(new java.awt.Dimension(400, 165));
        jPanel1.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.CENTER, 0, 0));

        panelInstalar.setBackground(new java.awt.Color(255, 255, 255));
        panelInstalar.setMaximumSize(new java.awt.Dimension(400, 40));
        panelInstalar.setMinimumSize(new java.awt.Dimension(400, 40));
        panelInstalar.setPreferredSize(new java.awt.Dimension(400, 40));
        panelInstalar.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.CENTER, 0, 0));

        instalarCertificado.setBackground(new java.awt.Color(255, 255, 255));
        instalarCertificado.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        instalarCertificado.setText("Instalar Certificado");
        instalarCertificado.setBorder(new javax.swing.border.LineBorder(new java.awt.Color(0, 0, 0), 1, true));
        instalarCertificado.setPreferredSize(new java.awt.Dimension(110, 21));
        instalarCertificado.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                instalarCertificadoActionPerformed(evt);
            }
        });
        panelInstalar.add(instalarCertificado);

        jPanel1.add(panelInstalar);

        jPanel3.setBackground(new java.awt.Color(255, 255, 255));
        jPanel3.setMaximumSize(new java.awt.Dimension(400, 105));
        jPanel3.setMinimumSize(new java.awt.Dimension(400, 105));
        jPanel3.setPreferredSize(new java.awt.Dimension(400, 105));
        jPanel3.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.CENTER, 0, 0));

        panelContraseñaError.setBackground(new java.awt.Color(255, 255, 255));
        panelContraseñaError.setMaximumSize(new java.awt.Dimension(400, 105));
        panelContraseñaError.setMinimumSize(new java.awt.Dimension(400, 105));
        panelContraseñaError.setPreferredSize(new java.awt.Dimension(400, 105));
        panelContraseñaError.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        jLabel5.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        jLabel5.setForeground(new java.awt.Color(255, 0, 51));
        jLabel5.setText("Contraseña:");
        panelContraseñaError.add(jLabel5, new org.netbeans.lib.awtextra.AbsoluteConstraints(120, 43, -1, -1));

        campoPass1.setText("jPasswordField1");
        campoPass1.setMaximumSize(new java.awt.Dimension(111, 20));
        campoPass1.setMinimumSize(new java.awt.Dimension(111, 20));
        campoPass1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                campoPass1ActionPerformed(evt);
            }
        });
        panelContraseñaError.add(campoPass1, new org.netbeans.lib.awtextra.AbsoluteConstraints(180, 40, 111, 20));

        jLabel6.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        jLabel6.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel6.setText("La contraseña que ingresó es incorrecta. Intente nuevamente.");
        panelContraseñaError.add(jLabel6, new org.netbeans.lib.awtextra.AbsoluteConstraints(50, 10, -1, -1));

        descargar1.setBackground(new java.awt.Color(255, 255, 255));
        descargar1.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        descargar1.setText("Descargar");
        descargar1.setBorder(new javax.swing.border.LineBorder(new java.awt.Color(0, 0, 0), 1, true));
        descargar1.setPreferredSize(new java.awt.Dimension(80, 21));
        descargar1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                descargar1ActionPerformed(evt);
            }
        });
        panelContraseñaError.add(descargar1, new org.netbeans.lib.awtextra.AbsoluteConstraints(210, 80, -1, -1));

        descargar2.setBackground(new java.awt.Color(255, 255, 255));
        descargar2.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        descargar2.setText("Instalar");
        descargar2.setBorder(new javax.swing.border.LineBorder(new java.awt.Color(0, 0, 0), 1, true));
        descargar2.setPreferredSize(new java.awt.Dimension(80, 21));
        descargar2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                descargar2ActionPerformed(evt);
            }
        });
        panelContraseñaError.add(descargar2, new org.netbeans.lib.awtextra.AbsoluteConstraints(120, 80, -1, -1));

        jPanel3.add(panelContraseñaError);

        jPanel1.add(jPanel3);

        jPanel2.setBackground(new java.awt.Color(255, 255, 255));
        jPanel2.setMaximumSize(new java.awt.Dimension(400, 105));
        jPanel2.setMinimumSize(new java.awt.Dimension(400, 105));
        jPanel2.setPreferredSize(new java.awt.Dimension(400, 105));
        jPanel2.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.CENTER, 0, 0));

        panelContraseña.setBackground(new java.awt.Color(255, 255, 255));
        panelContraseña.setMaximumSize(new java.awt.Dimension(400, 105));
        panelContraseña.setMinimumSize(new java.awt.Dimension(400, 105));
        panelContraseña.setPreferredSize(new java.awt.Dimension(400, 105));
        panelContraseña.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        jLabel1.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        jLabel1.setText("Contraseña:");
        panelContraseña.add(jLabel1, new org.netbeans.lib.awtextra.AbsoluteConstraints(120, 43, -1, -1));

        campoPass.setText("jPasswordField1");
        campoPass.setMaximumSize(new java.awt.Dimension(111, 20));
        campoPass.setMinimumSize(new java.awt.Dimension(111, 20));
        campoPass.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                campoPassActionPerformed(evt);
            }
        });
        panelContraseña.add(campoPass, new org.netbeans.lib.awtextra.AbsoluteConstraints(180, 40, 111, 20));

        jLabel2.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        jLabel2.setText("Ingrese la contraseña de su certificado y clave privada.");
        panelContraseña.add(jLabel2, new org.netbeans.lib.awtextra.AbsoluteConstraints(70, 10, 270, -1));

        descargar.setBackground(new java.awt.Color(255, 255, 255));
        descargar.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        descargar.setText("Descargar");
        descargar.setBorder(new javax.swing.border.LineBorder(new java.awt.Color(0, 0, 0), 1, true));
        descargar.setPreferredSize(new java.awt.Dimension(80, 21));
        descargar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                descargarActionPerformed(evt);
            }
        });
        panelContraseña.add(descargar, new org.netbeans.lib.awtextra.AbsoluteConstraints(210, 80, -1, -1));

        descargar3.setBackground(new java.awt.Color(255, 255, 255));
        descargar3.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        descargar3.setText("Instalar");
        descargar3.setBorder(new javax.swing.border.LineBorder(new java.awt.Color(0, 0, 0), 1, true));
        descargar3.setPreferredSize(new java.awt.Dimension(80, 21));
        descargar3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                descargar3ActionPerformed(evt);
            }
        });
        panelContraseña.add(descargar3, new org.netbeans.lib.awtextra.AbsoluteConstraints(120, 80, -1, -1));

        jPanel2.add(panelContraseña);

        jPanel1.add(jPanel2);

        jPanel4.setBackground(new java.awt.Color(255, 255, 255));
        jPanel4.setMaximumSize(new java.awt.Dimension(400, 105));
        jPanel4.setMinimumSize(new java.awt.Dimension(400, 105));
        jPanel4.setPreferredSize(new java.awt.Dimension(400, 105));
        jPanel4.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.CENTER, 0, 0));

        panelFinalizada.setBackground(new java.awt.Color(255, 255, 255));
        panelFinalizada.setMaximumSize(new java.awt.Dimension(400, 105));
        panelFinalizada.setMinimumSize(new java.awt.Dimension(400, 105));
        panelFinalizada.setPreferredSize(new java.awt.Dimension(400, 105));
        panelFinalizada.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        jLabel4.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        jLabel4.setText("Su certificado se descargó correctamente en su equipo");
        panelFinalizada.add(jLabel4, new org.netbeans.lib.awtextra.AbsoluteConstraints(70, 10, -1, -1));

        jPanel4.add(panelFinalizada);

        jPanel1.add(jPanel4);

        jPanel5.setBackground(new java.awt.Color(255, 255, 255));
        jPanel5.setMaximumSize(new java.awt.Dimension(400, 105));
        jPanel5.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.CENTER, 0, 0));

        panelFinalizada1.setBackground(new java.awt.Color(255, 255, 255));
        panelFinalizada1.setMaximumSize(new java.awt.Dimension(400, 105));
        panelFinalizada1.setMinimumSize(new java.awt.Dimension(400, 105));
        panelFinalizada1.setPreferredSize(new java.awt.Dimension(400, 105));
        panelFinalizada1.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        jLabel7.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        jLabel7.setText("Su certificado se instaló correctamente en su equipo");
        panelFinalizada1.add(jLabel7, new org.netbeans.lib.awtextra.AbsoluteConstraints(70, 10, -1, -1));

        jPanel5.add(panelFinalizada1);

        jPanel1.add(jPanel5);

        getContentPane().add(jPanel1);
    }// </editor-fold>//GEN-END:initComponents

    private void instalarCertificadoActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_instalarCertificadoActionPerformed
        try {
            //Si no es trustedX se mantiene como antes este codigo.
            if (!UtilesTrustedX.isTrustedX()){
                boolean encontre = verificarCertificadoLocal();
                if (encontre) {
                    mostrarContraseña();
                } 
                else {
                    this.mostrarSoloInstalar();
                    desplegarErrorNoExiste();
                }                             
            }
            else{
                jLabel2.setText("Ingrese la contraseña de firma.");
                jLabel2.setHorizontalAlignment(JLabel.CENTER);
                mostrarContraseña();
            }
        } catch (Exception ex) {
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            desplegarError();
            this.mostrarSoloInstalar();
        }
    }//GEN-LAST:event_instalarCertificadoActionPerformed

    private void descargarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_descargarActionPerformed
        try {
            char[] pass = campoPass1.getPassword();

            if (UtilesTrustedX.isTrustedX() ){
                desplegarErrorStr(Utiles.MENSAJE_ERROR);
            }
            else{
                PrivateKey privada = (PrivateKey) keysLocal.getKey(alias, pass);
                if(guardarCertificado(privada, certFirmado, certCA, pass)){
                    mostrarFinalizada2();
                }
            }
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            desplegarError();
            this.mostrarSoloInstalar();
        } catch (IOException ex) {
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            desplegarError();
            this.mostrarSoloInstalar();
        } catch (CertificateException ex) {
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            desplegarError();
            this.mostrarSoloInstalar();
        } catch (KeyStoreException ex) {
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            desplegarError();
            this.mostrarSoloInstalar();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            desplegarError();
            this.mostrarSoloInstalar();
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            mostrarContraseñaError();
        }
        
    }//GEN-LAST:event_descargarActionPerformed

    private void descargar1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_descargar1ActionPerformed
        try {
            char[] pass = campoPass1.getPassword();
            
            if (UtilesTrustedX.isTrustedX()){
                desplegarErrorStr(Utiles.MENSAJE_ERROR);
            }
            else{
                PrivateKey privada = (PrivateKey) keysLocal.getKey(alias, pass);
                if(guardarCertificado(privada, certFirmado, certCA, pass)){
                    mostrarFinalizada2();
                }                
            }
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            desplegarError();
            this.mostrarSoloInstalar();
        } catch (IOException ex) {
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            desplegarError();
            this.mostrarSoloInstalar();
        } catch (CertificateException ex) {
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            desplegarError();
            this.mostrarSoloInstalar();
        } catch (KeyStoreException ex) {
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            desplegarError();
            this.mostrarSoloInstalar();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            desplegarError();
            this.mostrarSoloInstalar();
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            mostrarContraseñaError();
        }
}//GEN-LAST:event_descargar1ActionPerformed

    private void campoPass1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_campoPass1ActionPerformed
        // TODO add your handling code here:
}//GEN-LAST:event_campoPass1ActionPerformed

    private void campoPassActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_campoPassActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_campoPassActionPerformed

    private void descargar2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_descargar2ActionPerformed
          try {
            char[] pass = campoPass1.getPassword();
            if (UtilesTrustedX.isTrustedX()){
                Thread thread = new Thread(){
                    @Override
                    public void run(){
                        try{
                            jLabel6.setText( MSJ_ESPERA );
                            jLabel6.setHorizontalAlignment( JLabel.CENTER ); 
                            instalarCertificadoTrustedX();
                            //cerrarBloqueModal();
                            mostrarFinalizada2();
                            
                        } catch (SWException ex) {
                            //cerrarBloqueModal();
                            System.out.println("Tipo: " + ex.getTipo());
                            System.out.println("Mensaje: " + ex.getMensaje());
                            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
                            if (SWException.ERROR_DE_AUTENTICACION.equals(ex.getTipo())){
                                mostrarContraseñaError();
                            }
                            else{
                                desplegarErrorStr(ex.getMensaje());
                            }
                        } catch (IOException ex) {
                            //cerrarBloqueModal();
                            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
                            System.out.println("Class: " + ex.getClass().getName());
                            System.out.println("Mensaje: " + ex.getMessage());            
                            desplegarError();
                            mostrarSoloInstalar();
                        } catch (CertificateException ex) {
                            //cerrarBloqueModal();
                            System.out.println("Class: " + ex.getClass().getName());
                            System.out.println("Mensaje: " + ex.getMessage());            
                            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
                            desplegarError();
                            mostrarSoloInstalar();
                        } catch (NoSuchAlgorithmException ex) {
                            //cerrarBloqueModal();
                            System.out.println("Class: " + ex.getClass().getName());
                            System.out.println("Mensaje: " + ex.getMessage());            
                            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
                            desplegarError();
                            mostrarSoloInstalar();
                        } catch (Exception ex){
                            //cerrarBloqueModal();
                            System.out.println("Class: " + ex.getClass().getName());
                            System.out.println("Mensaje: " + ex.getMessage());            
                            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
                            desplegarError();            
                        } 
                    }
                };
                //abrirBloqueoModal();
                thread.start();
                jLabel7.setText("Su certificado se instaló correctamente en TrustedX.");
                jLabel7.setHorizontalAlignment(JLabel.CENTER);                
            }
            else{
                PrivateKey privada = (PrivateKey) keysLocal.getKey(alias, pass);
                if(instalarCertificadoLocal(privada, certFirmado, pass)){
                    mostrarFinalizada2();
                }
            }
        } catch (NoSuchProviderException ex) {
            cerrarBloqueModal();
            System.out.println("Class: " + ex.getClass().getName());
            System.out.println("Mensaje: " + ex.getMessage());
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            desplegarError();
            this.mostrarSoloInstalar();
        } catch (IOException ex) {
            cerrarBloqueModal();
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            System.out.println("Class: " + ex.getClass().getName());
            System.out.println("Mensaje: " + ex.getMessage());            
            desplegarError();
            this.mostrarSoloInstalar();
        } catch (CertificateException ex) {
            cerrarBloqueModal();
            System.out.println("Class: " + ex.getClass().getName());
            System.out.println("Mensaje: " + ex.getMessage());            
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            desplegarError();
            this.mostrarSoloInstalar();
        } catch (KeyStoreException ex) {
            cerrarBloqueModal();
            System.out.println("Class: " + ex.getClass().getName());
            System.out.println("Mensaje: " + ex.getMessage());            
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            desplegarErrorStr("El certificado que intenta instalar ya se encuentra instalado.");
            this.mostrarSoloInstalar();
        } catch (NoSuchAlgorithmException ex) {
            cerrarBloqueModal();
            System.out.println("Class: " + ex.getClass().getName());
            System.out.println("Mensaje: " + ex.getMessage());            
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            desplegarError();
            this.mostrarSoloInstalar();
        } catch (UnrecoverableKeyException ex) {
            cerrarBloqueModal();
            System.out.println("Class: " + ex.getClass().getName());
            System.out.println("Mensaje: " + ex.getMessage());            
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            mostrarContraseñaError();
        } catch (Exception ex){
            cerrarBloqueModal();
            System.out.println("Class: " + ex.getClass().getName());
            System.out.println("Mensaje: " + ex.getMessage());            
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            desplegarError();            
        }
    }//GEN-LAST:event_descargar2ActionPerformed

    private void descargar3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_descargar3ActionPerformed
        try {
            char[] pass = campoPass1.getPassword();

            if (UtilesTrustedX.isTrustedX() ){               
                Thread thread = new Thread(){
                    @Override
                    public void run(){
                        try{
                            jLabel2.setText( MSJ_ESPERA );
                            jLabel2.setHorizontalAlignment( JLabel.CENTER ); 
                            instalarCertificadoTrustedX();
                            //cerrarBloqueModal();
                            mostrarFinalizada2();
                            
                        } catch (SWException ex) {
                            //cerrarBloqueModal();
                            System.out.println("Tipo: " + ex.getTipo());
                            System.out.println("Mensaje: " + ex.getMensaje());
                            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
                            if (SWException.ERROR_DE_AUTENTICACION.equals(ex.getTipo())){
                                mostrarContraseñaError();
                            }
                            else{
                                desplegarErrorStr(ex.getMensaje());
                            }
                        } catch (IOException ex) {
                            //cerrarBloqueModal();
                            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
                            System.out.println("Class: " + ex.getClass().getName());
                            System.out.println("Mensaje: " + ex.getMessage());            
                            desplegarError();
                            mostrarSoloInstalar();
                        } catch (CertificateException ex) {
                            //cerrarBloqueModal();
                            System.out.println("Class: " + ex.getClass().getName());
                            System.out.println("Mensaje: " + ex.getMessage());            
                            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
                            desplegarError();
                            mostrarSoloInstalar();
                        } catch (NoSuchAlgorithmException ex) {
                            //cerrarBloqueModal();
                            System.out.println("Class: " + ex.getClass().getName());
                            System.out.println("Mensaje: " + ex.getMessage());            
                            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
                            desplegarError();
                            mostrarSoloInstalar();
                        } catch (Exception ex){
                            //cerrarBloqueModal();
                            System.out.println("Class: " + ex.getClass().getName());
                            System.out.println("Mensaje: " + ex.getMessage());            
                            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
                            desplegarError();            
                        } 
                    }
                }; 
                thread.start();
                jLabel7.setText("Su certificado se instaló correctamente en TrustedX.");
                jLabel7.setHorizontalAlignment(JLabel.CENTER);                  
            }
            else{
                PrivateKey privada = (PrivateKey) keysLocal.getKey(alias, pass);
                if(instalarCertificadoLocal(privada, certFirmado, pass)){
                    mostrarFinalizada2();
                }
            }
        } catch (NoSuchProviderException ex) {
            cerrarBloqueModal();
            System.out.println("Class: " + ex.getClass().getName());
            System.out.println("Mensaje: " + ex.getMessage());             
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            desplegarError();
            this.mostrarSoloInstalar();
        } catch (IOException ex) {
            cerrarBloqueModal();
            System.out.println("Class: " + ex.getClass().getName());
            System.out.println("Mensaje: " + ex.getMessage());             
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            desplegarError();
            this.mostrarSoloInstalar();
        } catch (CertificateException ex) {
            cerrarBloqueModal();
            System.out.println("Class: " + ex.getClass().getName());
            System.out.println("Mensaje: " + ex.getMessage());             
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            desplegarError();
            this.mostrarSoloInstalar();
        } catch (KeyStoreException ex) {
            cerrarBloqueModal();
            System.out.println("Class: " + ex.getClass().getName());
            System.out.println("Mensaje: " + ex.getMessage());             
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            desplegarErrorStr("El certificado que intenta instalar ya se encuentra instalado.");
            this.mostrarSoloInstalar();
        } catch (NoSuchAlgorithmException ex) {
            cerrarBloqueModal();
            System.out.println("Class: " + ex.getClass().getName());
            System.out.println("Mensaje: " + ex.getMessage());             
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            desplegarError();
            this.mostrarSoloInstalar();
        } catch (UnrecoverableKeyException ex) {
            cerrarBloqueModal();
            System.out.println("Class: " + ex.getClass().getName());
            System.out.println("Mensaje: " + ex.getMessage());             
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            mostrarContraseñaError();
        } catch (Exception ex){
            cerrarBloqueModal();
            System.out.println("Class: " + ex.getClass().getName());
            System.out.println("Mensaje: " + ex.getMessage());            
            Logger.getLogger(ResponseApplet.class.getName()).log(Level.SEVERE, null, ex);
            desplegarError();            
        }      
    }//GEN-LAST:event_descargar3ActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JPasswordField campoPass;
    private javax.swing.JPasswordField campoPass1;
    private javax.swing.JButton descargar;
    private javax.swing.JButton descargar1;
    private javax.swing.JButton descargar2;
    private javax.swing.JButton descargar3;
    private javax.swing.JButton instalarCertificado;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JPanel jPanel5;
    private javax.swing.JPanel panelContraseña;
    private javax.swing.JPanel panelContraseñaError;
    private javax.swing.JPanel panelFinalizada;
    private javax.swing.JPanel panelFinalizada1;
    private javax.swing.JPanel panelInstalar;
    // End of variables declaration//GEN-END:variables

    private boolean instalarCertificadoLocal(PrivateKey privada, X509Certificate certFirmado, char[] pass) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException {
          
            KeyStore ks = Utiles.obtenerKeyStoreDesdeAlmacen();
            ks.setCertificateEntry(certFirmado.getSerialNumber().toString(), certFirmado);

            ks.setKeyEntry(certFirmado.getSerialNumber().toString(), privada, pass, new Certificate[]{certFirmado});
            Utiles.guardarKeyStoreEnAlmacen(ks);

        return true;
    }

}
