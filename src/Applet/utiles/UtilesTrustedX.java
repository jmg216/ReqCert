/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Applet.utiles;

import com.isa.SW.SWHelperFactory;
import com.isa.SW.entities.User;
import com.isa.SW.exceptions.SWException;
import com.isa.SW.services.ServicioAA;
import com.isa.SW.services.ServicioEP;
import com.isa.SW.services.ServicioKM;
import com.isa.SW.utils.UtilesResources;
import com.isa.SW.utils.UtilesSWHelper;
import com.isa.SW.utils.XMLServiceGenerator;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 *
 * @author JMiraballes
 * 
 * Clase que contiene todos los accesos al SmartWrapperHelper, que a su 
 * vez se comunica con smartwrapper.
 * De esta forma se encapsula en un solo puntos, todos
 * los accesos a los servicios proporcionados por la
 * plataforma, y mas específicamente a los metodos proporcionados por smartwrapper
 * a través de SmartWrapperHelper.
 */
public class UtilesTrustedX {
    
    //Varible que indica si se utilizará la plataforma trustedX o
    //se utilizará la los directorios locales para almacenar y registrar
    //las claves.
    //Esta variable es estática y su valor se comparte en toda la aplicación.
    private static boolean isTrustedX;
    
    public static String TRUSTED_PARAM = "isTrusted";
    public static String TRUSTED_VALUE = "true";    
    
    public static void setIsTrustedX( boolean param){
        isTrustedX = param;
    }
    
    public static boolean isTrustedX() {
        return isTrustedX;
    }
    
    /**
     * Registra un usuario sino existe.
     * 
     * @param artifact
     * @param usuario
     * @throws com.isa.SW.exceptions.SWException
     * @throws java.io.IOException
     */
    public static void registrarUsuario(String artifact, User usuario) throws SWException, IOException{
        
        String xPath = XMLServiceGenerator.getUserXPath(usuario.getsNameUID(), usuario.getoNameOU());
        String xPathClaves = XMLServiceGenerator.getAlmacenClavesXPath(usuario.getsNameUID(), usuario.getoNameOU());
        ServicioEP serv = SWHelperFactory.createServiceEP();
        
        //Si existe se elimina y se crea nuevamente.
        if (serv.existe(artifact, xPath)){  
            //eliminar almancen de claves si existe
            if (serv.existe(artifact, xPathClaves)){
                serv.eliminar(artifact, xPathClaves);
            }
            //eliminar usuario existente
            serv.eliminar(artifact, xPath);
        }
        String xPathInsert = XMLServiceGenerator.XPATH_USER;
        String data = XMLServiceGenerator.generarUsuarioXML( usuario );
        serv.insert(artifact, xPathInsert, data);
    }
    
    /**
     * Método que genera un pkcs10 en trustedX. Deuvelve el pkcs10 en base 64.
     * Se le pasa por parámetro los datos del usuario.
     * 
     * @param artifact
     * @param usuario
     * @return 
     * @throws com.isa.SW.exceptions.SWException 
     */
    public static String generarPKCS10(String artifact, User usuario   ) throws SWException{
        ServicioKM servKM = SWHelperFactory.createServiceKM();
        String dn =  Utiles.getDN(usuario.getsNameUID(), usuario.getoNameOU());
        String key = servKM.generarPKCS10(artifact, dn );
        return key;
    }
    
    public static String generarX509(User usuario ) throws SWException{
        ServicioKM servKM = SWHelperFactory.createServiceKM();
        String dn =  Utiles.getDN(usuario.getsNameUID(), usuario.getoNameOU());
        String key = servKM.generar509Certificado( usuario.getsNameUID(), usuario.getSNamePasswd(), dn );
        return key;
    }
    
    /**
     * Método que instala un certificado en trustedx.
     * Se le pasa por parámetro el certificado root de la CA, el certificado
     * firmado y el DN del usuario.
     * 
     * @param artifact
     * @param certCA
     * @param certFirmado
     * @param dn
     * @throws com.isa.SW.exceptions.SWException
     * @throws java.security.cert.CertificateException
     * @throws java.security.NoSuchAlgorithmException
     */
    public static void instalarCertificado (String artifact, String certCA, String certFirmado, String dn) throws SWException, CertificateException, NoSuchAlgorithmException {
        ServicioKM servKM = SWHelperFactory.createServiceKM();
        
        X509Certificate cer = Utiles.decodeCertificate(certCA);
        String thumbPrint =  Utiles.getThumbPrint(cer);
        
        servKM.insertarCertificado(artifact, certCA, thumbPrint, certFirmado, dn);
    }
    
    /**
     * Instala un certificado pkcs12 en trustedx. Se pasa por parámetros el usuario,
     * la huella digital del certificado, los datos de pkcs12 en base64 y el password
     * que custodia la clvae privada.
     * 
     * @param usuario
     * @param certRoot
     * @param pkPass
     * @param footPrint
     * @param dataPKCS12
     * @throws com.isa.SW.exceptions.SWException
     * @throws java.io.IOException
     */
    public static void instalarPKCS1k2(User usuario, String certRoot, String footPrint, String dataPKCS12, String pkPass) throws SWException, IOException{
        ServicioKM servKM = SWHelperFactory.createServiceKM();
        String dn = Utiles.getDN(usuario.getsNameUID(), usuario.getoNameOU());
        servKM.insertarContenedorPKCS12(UtilesSWHelper.getAdminUsuario(), UtilesSWHelper.getAdminPassword(), dn, certRoot, footPrint, dataPKCS12, pkPass);
    }
    
    
    /**
     * Modifica el password del usuario pasado por parámetro.
     * @param artifact
     * @param usuario
     * @param passwordAnt
     * @param password
     * @return 
     * @throws com.isa.SW.exceptions.SWException
     * @throws java.io.IOException
     */
    public static boolean modificarPassword(String artifact, String usuario, String password ) throws SWException, IOException{
        
            ServicioEP servEP = SWHelperFactory.createServiceEP();
            String dn =  Utiles.getDN(usuario, UtilesResources.getProperty("swHelperConfig.trustedOU"));
            return servEP.modificarPassword(artifact, dn, password);
        
    }
    
    public static String getEntidadUsuario (String artifact, String usuario ) throws IOException, SWException{
        
            String dn =  Utiles.getDN(usuario, UtilesResources.getProperty("swHelperConfig.trustedOU"));
            String xPath = XMLServiceGenerator.XPATH_USER + "/User[@dname='"+ dn +"']";
            ServicioEP servEP = SWHelperFactory.createServiceEP();
            String xmlUsuario = servEP.read(artifact, xPath);
            return XMLServiceGenerator.getAtributoEntity(xmlUsuario, XMLServiceGenerator.TAG_USUARIO_PASSWD);
    }
    
    /**
     * 
     * @param usuario
     * @param password
     * @return 
     * @throws com.isa.SW.exceptions.SWException 
     */
    public static String login( String usuario, String password ) throws SWException{
        ServicioAA servAA = SWHelperFactory.createServiceAA();
        
        return servAA.login( usuario, password );
    }
    
    public static void logout( String usuario, String artifact ) throws SWException{
        ServicioAA servAA = SWHelperFactory.createServiceAA();
        
        servAA.logut(usuario, artifact);
    }
   
}
