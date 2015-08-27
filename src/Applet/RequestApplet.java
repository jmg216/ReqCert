/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * RequestApplet.java
 *
 * Created on 11/02/2011, 11:16:19 AM
 */

package Applet;

import Applet.utiles.Utiles;
import Applet.utiles.UtilesTrustedX;
import com.isa.SW.SWHelperFactory;
import com.isa.SW.entities.User;
import com.isa.SW.exceptions.SWException;
import com.isa.SW.services.ServicioEP;
import com.isa.SW.utils.UtilesResources;
import com.isa.SW.utils.UtilesSWHelper;
import com.isa.SW.utils.XMLServiceGenerator;
import java.awt.Color;
import java.awt.Cursor;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JOptionPane;
import javax.swing.UIManager;
import javax.swing.border.Border;
import javax.swing.border.LineBorder;
import netscape.javascript.JSObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.x509.X509V3CertificateGenerator;


/**
 *
 * @author ISA
 */
public class RequestApplet extends javax.swing.JApplet {

    private String artifact;
    private String artifact2;
    
    /** Initializes the applet RequestApplet */
    @Override
    public void init() {
        UtilesSWHelper.setCodeBase(getCodeBase());
        UtilesTrustedX.setIsTrustedX( getParameter(UtilesTrustedX.TRUSTED_PARAM).equals(UtilesTrustedX.TRUSTED_VALUE) );
        Utiles.addProvider();
        this.initComponents();
        initButton();      
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

    private int obtenerKeySize() {
        JSObject win = (JSObject) JSObject.getWindow(this);
        String size = (String) win.eval("obtenerKeySize()");
        if (size.equals("4096")){
            return 4096;
        }else if(size.equals("2048")){
            return 2048;
        }else{
            return 1024;
        }
    }
    
    /**
     * Retorna el usuario logueado.
     * @return 
     */
    public String obtenerUsuario(){
        return getParameter("usuario");
    }
    
    private void abrirBloqueoModal(){
        JSObject win = (JSObject) JSObject.getWindow(this);
        win.eval("abrirProcesandoApplet()"); 
    }

    private void cerrarBloqueModal(){
        JSObject win = (JSObject) JSObject.getWindow(this);
        win.eval("cerrarProcesandoApplet()");            
    }

    private void desplegarFinalizado() {
        JSObject win = (JSObject) JSObject.getWindow(this);
        win.eval("desplegarFinalizado()");
    }

    private void desplegarError() {
        JSObject win = (JSObject) JSObject.getWindow(this);
        win.eval("desplegarError()");
    }
    
    private void desplegarErrorMsj(String str) {
        JSObject win = (JSObject) JSObject.getWindow(this);
        win.eval("desplegarErrorMsj(\""+ str +"\")");
    }

    private String validarEntradas() {
        JSObject win = (JSObject) JSObject.getWindow(this);
        return (String) win.eval("validarEntradas()");
    }

    private void enviarRequest(String reqString) {
        JSObject win = (JSObject) JSObject.getWindow(this);
        win.call("setPublicKeyInfo", new String[]{reqString});
    }

    private char[] obtenerPassword() {
        JSObject win = (JSObject) JSObject.getWindow(this);
        String aRet = (String) win.call("getPassword",null);
        return aRet.toCharArray();
    }
    

    private X509Certificate generateCertificate(KeyPair pair, String nombreUsuario) throws CertificateEncodingException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, InvalidKeyException{
            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
            X509Name name = new X509Name("CN="+nombreUsuario);
            BigInteger bi = BigInteger.valueOf(System.currentTimeMillis());
            certGen.setSerialNumber(bi);
            certGen.setIssuerDN(name);
            certGen.setNotBefore(new Date(System.currentTimeMillis()));
            long sixMonth = (long) 1000.0 * 60 * 60 * 24 * 30 * 6;
            certGen.setNotAfter(new Date(System.currentTimeMillis()+sixMonth));
            
            certGen.setSubjectDN(name);                       // note: same as issuer
            certGen.setPublicKey(pair.getPublic());
            certGen.setSignatureAlgorithm("MD5withRSA");
            X509Certificate cert = certGen.generate(pair.getPrivate(), "BC");
            return cert;
    }
    
    private PKCS10CertificationRequest generateRequest(KeyPair pair, String nombreUsuario) throws NoSuchAlgorithmException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchProviderException, InvalidKeyException, InvalidKeyException, SignatureException, IOException {         
        Vector<DERObjectIdentifier> oids = new Vector<DERObjectIdentifier>();
        Vector<X509Extension> values = new Vector<X509Extension>();
        oids.add(X509Extensions.KeyUsage);
        values.add(new X509Extension(true, new DEROctetString(new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.nonRepudiation))));
        oids.add(X509Extensions.ExtendedKeyUsage);
        values.add(new X509Extension(false, new DEROctetString(new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth))));

        X509Extensions extensions = new X509Extensions(oids, values);
        Attribute attribute = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,new DERSet(extensions));
        return new PKCS10CertificationRequest("MD5withRSA", new X509Name("CN="+nombreUsuario), pair.getPublic(), new DERSet(attribute), pair.getPrivate());
    }
    
    /**
     Genera un par de claves dado un algoritmo RSA y el provider BC y largo
     * pasado por parámetro.
     */
    private KeyPair generateKeyPair(int keysize) throws NoSuchAlgorithmException, NoSuchProviderException{
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        kpGen.initialize(keysize, new SecureRandom());
        KeyPair pair = kpGen.generateKeyPair();
        return pair;
    }
    
    /**
     * Genenra la certificado a partir de las credenciales del usuario.
     * y se guarda en el keystore local.
    */
    private String generateCertificateLocal( String nombreUsuario, char[] passUsuario, int keySize) throws Exception {

        KeyPair pair = generateKeyPair(keySize);
        //Generación PKCS10 asociada a usuario.
        PKCS10CertificationRequest request = generateRequest(pair, nombreUsuario);
        
        //Conversión de PKCS10 a Base 64
        String reqString = Utiles.convertPKCS10ToBase64(request);
        
        X509Certificate cert = generateCertificate(pair, nombreUsuario);
        System.out.println(cert.getPublicKey().equals(pair.getPublic()));
        System.out.println(cert);
        
        //Conversión de certificados a base 64
        String certString = Utiles.convertX509ToBase64(cert);
        System.out.println(certString);
        
        //Obtiene keystore
        KeyStore ks = Utiles.obtenerKeyStore();
        
        //Asigna el certificado al alias.
        ks.setCertificateEntry(cert.getSerialNumber().toString(), cert);
        //Asigna la clave privada al alias del certificado protegido por el password dado.
        ks.setKeyEntry(cert.getSerialNumber().toString(), pair.getPrivate(), passUsuario, new Certificate[]{cert});
            //Se guarda keystore en :APPDATA/IGDoc
        Utiles.guardarKeyStore(ks);
        return reqString;
    }
    
    
    
    private String generateCertificateTrustedX() throws Exception  {
        
        try {
            User user = new User();
            user.setsNameUID( obtenerUsuario() );
            user.setSNamePasswd(Utiles.convertToSHA256(String.valueOf(obtenerPassword())));
            user.setoNameO("");
            user.setoNameOU( UtilesResources.getProperty("swHelperConfig.trustedOU"));
            user.setDescription("");
            user.setiName("");
            user.setLanguage("");
            user.setcNameTitle("");
            user.setcNameFName( "" );
            user.setcNameSurname( "" ); 
            user.setoNameTitle(""); 
            user.setContactsWorkMail("");
            user.setContactsWorkPhone("");  

            //Registra un usuario en trastedX 
            long startTime = System.currentTimeMillis();
            
            artifact = null;
            artifact = UtilesTrustedX.login(UtilesSWHelper.getAdminUsuario(), UtilesSWHelper.getAdminPassword());
            UtilesTrustedX.registrarUsuario(artifact, user);  
            UtilesTrustedX.logout(UtilesSWHelper.getAdminUsuario(), artifact);
            
            artifact2 = null;
            artifact2 = UtilesTrustedX.login(user.getsNameUID(), user.getSNamePasswd());
            String cert = UtilesTrustedX.generarPKCS10(artifact2, user);
            UtilesTrustedX.logout(user.getsNameUID(), artifact2);
            
            long endTime = System.currentTimeMillis();
            long timeResult = (endTime - startTime);
            
            System.out.println("TIEMPO TOTAL SOLICITUD: " + (Utiles.convertTimeMillisToSeconds(timeResult)) + " SEGUNDOS");
            
            return cert;
        }
        catch (SWException ex) {
            if (artifact != null){
                UtilesTrustedX.logout(UtilesSWHelper.getAdminUsuario(), artifact);
            }
            if (artifact2 != null){
                UtilesTrustedX.logout(obtenerUsuario(), artifact);
            }
            Logger.getLogger(RequestApplet.class.getName()).log(Level.SEVERE, null, ex);
            throw new Exception(ex.getMessage());
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

        getContentPane().setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 0, 0));

        jPanel1.setBackground(new java.awt.Color(255, 255, 255));
        jPanel1.setPreferredSize(new java.awt.Dimension(400, 200));
        jPanel1.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 0, 0));

        jButton1.setBackground(new java.awt.Color(57, 155, 255));
        jButton1.setFont(new java.awt.Font("SansSerif", 1, 12)); // NOI18N
        jButton1.setForeground(new java.awt.Color(255, 255, 255));
        jButton1.setText("Enviar Solicitud de Certificado");
        jButton1.setBorder(new javax.swing.border.LineBorder(new java.awt.Color(57, 155, 255), 5, true));
        jButton1.setBorderPainted(false);
        jButton1.setPreferredSize(new java.awt.Dimension(255, 30));
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });
        jPanel1.add(jButton1);

        getContentPane().add(jPanel1);
    }// </editor-fold>//GEN-END:initComponents

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        try {
            String nombreUsuario = obtenerUsuario();
            if (validarEntradas().equals("SI")){
                char[] passUsuario = obtenerPassword();
                StringBuilder mensajeError = new StringBuilder();
                if (Utiles.validarPassword(new String(passUsuario), mensajeError)){
                    int keySize = obtenerKeySize();
                    String reqString;
                    abrirBloqueoModal();
                    if (UtilesTrustedX.isTrustedX()){
                        reqString = generateCertificateTrustedX();
                        cerrarBloqueModal();
                    }
                    else{
                        reqString = generateCertificateLocal(nombreUsuario, passUsuario, keySize);
                    }
                    enviarRequest(reqString);
                    desplegarFinalizado();
                }
                else{
                    this.desplegarErrorMsj(mensajeError.toString());
                }
            }

        } catch (Exception ex) {
            if (UtilesTrustedX.isTrustedX()){
                cerrarBloqueModal();
            }
            Logger.getLogger(RequestApplet.class.getName()).log(Level.SEVERE, null, ex);
            this.desplegarError();
        }
    }//GEN-LAST:event_jButton1ActionPerformed



    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton1;
    private javax.swing.JPanel jPanel1;
    // End of variables declaration//GEN-END:variables

}
