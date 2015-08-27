/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * JavaApplet.java
 *
 * Created on 04/02/2011, 09:27:10 AM
 */

package Applet;

//import java.security.Certificate;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Francisco Alvarez
 */
public class ExportApplet extends javax.swing.JApplet {
    private String usuario;
    private HashMap certs;
    private HashMap aliasHash;
    private KeyStore keystore;
    private String seleccionado;
    private char[] contra;
    private int error;
    private boolean primera = true;
    private boolean eliminar = false;

    /** Initializes the applet JavaApplet */
    @Override
    public void init() {
        //Si es la primera vez que ejecuto el programa inicializo los componentes GUI
        if(primera){
            initComponents();
        }
        //inicializo las variables globales
        primera=false;
        okButton.setEnabled(false);
        okButton5.setEnabled(false);
        usuario = getParameter("usuario").toUpperCase();

        //Creo el modelo de la lista donde se muestran los certificados
        ListSelectionModel selm = lista.getSelectionModel();
        selm.addListSelectionListener(new ListSelectionListener() {
                                                public void valueChanged(ListSelectionEvent e) {
                                                    okButton.setEnabled(true);
                                                    okButton5.setEnabled(true);
                                                }
                                          });
        pass.setText("");
        pass1.setText("");
        //lista.addComponentListener(new ListListener());
        //lista.addItemListener(new ListListener());
        error=1;
        contra=null;

        //Seteo el tamaño del applet y muestro el panel principal
        this.resize(484, 169);
        principal.setVisible(true);
        noCerts.setVisible(false);
        password.setVisible(false);
        finalizar.setVisible(false);
        passwordError.setVisible(false);
        hayError.setVisible(false);
        finalizar2.setVisible(false);

        //Agrego el BouncyCastleProvider como proveedor.
        Security.addProvider(new BouncyCastleProvider());

        certs = new HashMap();
        aliasHash = new HashMap();
        cargarKeystore();
        if (certs.isEmpty()){
            //Si no encontré ningún certificado en ningúna de las almacenes, Muestro
            //el panel que informa lo dicho anteriormente.
            principal.setVisible(false);
            noCerts.setVisible(true);
            password.setVisible(false);
            finalizar.setVisible(false);
            passwordError.setVisible(false);
            hayError.setVisible(false);
            finalizar2.setVisible(false);
        }
    }

    //función que obtiene los certificados del almacén de java para el usuario logueado
    private void cargarKeystore(){
        Certificate c;
        String keystoreFilename;
        if(isOSWindows()){
            keystoreFilename = System.getenv("APPDATA").replace("\\", "/")+"/IGDoc/almacenIGDOC";
        }else{
            keystoreFilename = System.getProperty("user.home").replace("\\", "/")+"/.IGDoc/almacenIGDOC";
        }
        FileInputStream fIn = null;
        try {
            if((new File(keystoreFilename)).exists()){
                fIn = new FileInputStream(keystoreFilename);
                keystore = KeyStore.getInstance("JKS");
                keystore.load(fIn,"default".toCharArray());
                fIn.close();
                boolean valido;
                ArrayList<String[]> elementos = new ArrayList();
                String[] elem;
                Enumeration enumer = keystore.aliases();
                SimpleDateFormat simpDate = new SimpleDateFormat("dd/MM/yyyy");
                String fecha;
                //Recorro todos los certificados para insertar los certificados del usuario logueado
                for (; enumer.hasMoreElements(); ) {
                    valido = true;
                    String alias = (String)enumer.nextElement();
                    System.out.println("alias - " + alias);
                    c = (Certificate) keystore.getCertificate(alias);
                    X509Certificate x509cert = (X509Certificate)c;
                    Principal nombre = x509cert.getSubjectDN();
                    Principal emisor = x509cert.getIssuerDN();
                    String issuerDn = emisor.getName();
                    try{
                        x509cert.checkValidity();
                    } catch (CertificateExpiredException exe) {
                            valido = false;
                    } catch (CertificateNotYetValidException exe) {
                        valido = false;
                    }
                    String subjectDn = nombre.getName();
                    if(getCN(subjectDn).toUpperCase().equals(usuario) && valido){
                        //Si el certificado es del usuario y además es válido, entonces lo inserto en un HashMap de certificados.
                        fecha= simpDate.format(x509cert.getNotBefore())+"-"+simpDate.format(x509cert.getNotAfter());
                        elem = new String [] {getCN(subjectDn), getCN(issuerDn),fecha};
                        elementos.add(elem);
                        //lista.add(getCN(subjectDn)+" - "+getCN(issuerDn)+" - "+x509cert.getNotAfter());
                        certs.put(String.valueOf(certs.size()),x509cert);
                        aliasHash.put(String.valueOf(aliasHash.size()),alias);
                        //certs.put(getCN(subjectDn)+" - "+getCN(issuerDn)+" - "+fecha,x509cert);
                        //aliasHash.put(getCN(subjectDn)+" - "+getCN(issuerDn)+" - "+fecha,alias);
                    }
                    //Inicializo el modelo de la lista de certificados y además inserto los mismos.
                    MyTableModel modelo = new MyTableModel();
                    modelo.addColumn("Nombre");
                    modelo.addColumn("Emisor");
                    modelo.addColumn("Fecha de validez");
                    for(int i=0;i<elementos.size();i++){
                            modelo.addRow(elementos.get(i));
                    }
                    //MyTableModel modelo = new MyTableModel(auxElem,new String [] {"Nombre", "Emisor", "Fecha validez"});
                    lista.setModel(modelo);
                }
            }else{
                principal.setVisible(false);
                noCerts.setVisible(true);
                password.setVisible(false);
                passwordError.setVisible(false);
                finalizar.setVisible(false);
                hayError.setVisible(false);
                finalizar2.setVisible(false);
            }
            //Si ocurre algún error muestro el panel que informa.
        } catch (FileNotFoundException ex) {
            Logger.getLogger(ExportApplet.class.getName()).log(Level.SEVERE, null, ex);
            principal.setVisible(false);
            noCerts.setVisible(true);
            password.setVisible(false);
            passwordError.setVisible(false);
            finalizar.setVisible(false);
            hayError.setVisible(false);
            finalizar2.setVisible(false);
        } catch (IOException ex) {
            Logger.getLogger(ExportApplet.class.getName()).log(Level.SEVERE, null, ex);
            principal.setVisible(false);
            noCerts.setVisible(false);
            password.setVisible(false);
            passwordError.setVisible(false);
            finalizar.setVisible(false);
            hayError.setVisible(true);
            finalizar2.setVisible(false);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ExportApplet.class.getName()).log(Level.SEVERE, null, ex);
            principal.setVisible(false);
            noCerts.setVisible(false);
            password.setVisible(false);
            passwordError.setVisible(false);
            finalizar.setVisible(false);
            hayError.setVisible(true);
            finalizar2.setVisible(false);
        } catch (CertificateException ex) {
            Logger.getLogger(ExportApplet.class.getName()).log(Level.SEVERE, null, ex);
            principal.setVisible(false);
            noCerts.setVisible(false);
            password.setVisible(false);
            passwordError.setVisible(false);
            finalizar.setVisible(false);
            hayError.setVisible(true);
            finalizar2.setVisible(false);
        } catch (KeyStoreException ex) {
            Logger.getLogger(ExportApplet.class.getName()).log(Level.SEVERE, null, ex);
            principal.setVisible(false);
            noCerts.setVisible(false);
            password.setVisible(false);
            passwordError.setVisible(false);
            finalizar.setVisible(false);
            hayError.setVisible(true);
            finalizar2.setVisible(false);
        } finally {
            try {
                if(fIn != null)
                    fIn.close();
            } catch (IOException ex) {
                principal.setVisible(false);
                noCerts.setVisible(false);
                password.setVisible(false);
                passwordError.setVisible(false);
                finalizar.setVisible(false);
                hayError.setVisible(true);
                finalizar2.setVisible(false);
            }
        }
    }

    //Función para obtener el nombre identificado por CN=
    private String getCN(String nombre){
        String[] arreglo;
        arreglo = nombre.split(",");
        for(int i = 0;i<arreglo.length;i++){
            if(arreglo[i].startsWith(" CN=")||arreglo[i].startsWith("CN=")){
                if(arreglo[i].startsWith(" CN="))
                    return arreglo[i].replace(" CN=", "");
                else
                    return arreglo[i].replace("CN=", "");
            }
        }
        return "";
    }

    //Función que me indica si estoy en wondows.
    public static boolean isOSWindows() {
        return (System.getProperty("os.name").toLowerCase().startsWith("win"));
    }

    //Extension del modelo de la tabla para hacer que las celdas no sean editables.
    public class MyTableModel extends DefaultTableModel{

        @Override
        public boolean isCellEditable(int a, int b) {
                return false;
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

        contenedor = new javax.swing.JPanel();
        passwordError = new javax.swing.JPanel();
        titulo5 = new javax.swing.JLabel();
        pass1 = new javax.swing.JPasswordField();
        okButton2 = new javax.swing.JButton();
        titulo6 = new javax.swing.JLabel();
        titulo7 = new javax.swing.JLabel();
        cancelar = new javax.swing.JButton();
        finalizar = new javax.swing.JPanel();
        titulo3 = new javax.swing.JLabel();
        okButton6 = new javax.swing.JButton();
        noCerts = new javax.swing.JPanel();
        titulo2 = new javax.swing.JLabel();
        password = new javax.swing.JPanel();
        titulo1 = new javax.swing.JLabel();
        pass = new javax.swing.JPasswordField();
        okButton1 = new javax.swing.JButton();
        titulo4 = new javax.swing.JLabel();
        cancelar2 = new javax.swing.JButton();
        principal = new javax.swing.JPanel();
        okButton = new javax.swing.JButton();
        titulo = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        lista = new javax.swing.JTable();
        okButton5 = new javax.swing.JButton();
        hayError = new javax.swing.JPanel();
        titulo8 = new javax.swing.JLabel();
        okButton3 = new javax.swing.JButton();
        finalizar2 = new javax.swing.JPanel();
        titulo9 = new javax.swing.JLabel();
        okButton7 = new javax.swing.JButton();

        getContentPane().setLayout(new java.awt.GridLayout(1, 1));

        contenedor.setBackground(new java.awt.Color(255, 255, 255));
        contenedor.setPreferredSize(new java.awt.Dimension(484, 169));
        contenedor.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.CENTER, 0, 0));

        passwordError.setBackground(new java.awt.Color(255, 255, 255));
        passwordError.setMaximumSize(new java.awt.Dimension(484, 169));
        passwordError.setMinimumSize(new java.awt.Dimension(484, 169));
        passwordError.setPreferredSize(new java.awt.Dimension(484, 169));
        passwordError.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        titulo5.setFont(new java.awt.Font("Arial", 1, 11)); // NOI18N
        titulo5.setForeground(new java.awt.Color(0, 118, 196));
        titulo5.setText("Ingrese la contraseña de la clave privada de su certificado.");
        passwordError.add(titulo5, new org.netbeans.lib.awtextra.AbsoluteConstraints(80, 20, -1, -1));

        pass1.setMaximumSize(new java.awt.Dimension(104, 20));
        pass1.setMinimumSize(new java.awt.Dimension(104, 20));
        pass1.setPreferredSize(new java.awt.Dimension(104, 20));
        passwordError.add(pass1, new org.netbeans.lib.awtextra.AbsoluteConstraints(230, 68, -1, -1));

        okButton2.setBackground(new java.awt.Color(245, 244, 244));
        okButton2.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        okButton2.setText("Aceptar");
        okButton2.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 102, 204)));
        okButton2.setMaximumSize(new java.awt.Dimension(84, 20));
        okButton2.setMinimumSize(new java.awt.Dimension(84, 20));
        okButton2.setPreferredSize(new java.awt.Dimension(84, 20));
        okButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                okButton2ActionPerformed(evt);
            }
        });
        passwordError.add(okButton2, new org.netbeans.lib.awtextra.AbsoluteConstraints(155, 140, -1, -1));

        titulo6.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        titulo6.setForeground(new java.awt.Color(255, 0, 51));
        titulo6.setText("Contraseña:");
        passwordError.add(titulo6, new org.netbeans.lib.awtextra.AbsoluteConstraints(160, 70, -1, -1));

        titulo7.setFont(new java.awt.Font("Arial", 0, 10)); // NOI18N
        titulo7.setForeground(new java.awt.Color(255, 0, 51));
        titulo7.setText("contraseña incorrecta.");
        passwordError.add(titulo7, new org.netbeans.lib.awtextra.AbsoluteConstraints(230, 90, -1, -1));

        cancelar.setBackground(new java.awt.Color(245, 244, 244));
        cancelar.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        cancelar.setText("Cancelar");
        cancelar.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 102, 204)));
        cancelar.setMaximumSize(new java.awt.Dimension(84, 20));
        cancelar.setMinimumSize(new java.awt.Dimension(84, 20));
        cancelar.setPreferredSize(new java.awt.Dimension(84, 20));
        cancelar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cancelarActionPerformed(evt);
            }
        });
        passwordError.add(cancelar, new org.netbeans.lib.awtextra.AbsoluteConstraints(245, 140, -1, -1));

        contenedor.add(passwordError);

        finalizar.setBackground(new java.awt.Color(255, 255, 255));
        finalizar.setMaximumSize(new java.awt.Dimension(484, 169));
        finalizar.setMinimumSize(new java.awt.Dimension(484, 169));

        titulo3.setFont(new java.awt.Font("Arial", 1, 11)); // NOI18N
        titulo3.setForeground(new java.awt.Color(0, 118, 196));
        titulo3.setText("Se ha exportado correctamente el certificado.");

        okButton6.setBackground(new java.awt.Color(245, 244, 244));
        okButton6.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        okButton6.setText("Aceptar");
        okButton6.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 102, 204)));
        okButton6.setMaximumSize(new java.awt.Dimension(84, 20));
        okButton6.setMinimumSize(new java.awt.Dimension(84, 20));
        okButton6.setPreferredSize(new java.awt.Dimension(84, 20));
        okButton6.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                okButton6ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout finalizarLayout = new javax.swing.GroupLayout(finalizar);
        finalizar.setLayout(finalizarLayout);
        finalizarLayout.setHorizontalGroup(
            finalizarLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(finalizarLayout.createSequentialGroup()
                .addGroup(finalizarLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(finalizarLayout.createSequentialGroup()
                        .addGap(122, 122, 122)
                        .addComponent(titulo3))
                    .addGroup(finalizarLayout.createSequentialGroup()
                        .addGap(196, 196, 196)
                        .addComponent(okButton6, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(119, Short.MAX_VALUE))
        );
        finalizarLayout.setVerticalGroup(
            finalizarLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(finalizarLayout.createSequentialGroup()
                .addGap(74, 74, 74)
                .addComponent(titulo3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 50, Short.MAX_VALUE)
                .addComponent(okButton6, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        contenedor.add(finalizar);

        noCerts.setBackground(new java.awt.Color(255, 255, 255));
        noCerts.setMaximumSize(new java.awt.Dimension(484, 169));
        noCerts.setMinimumSize(new java.awt.Dimension(484, 169));

        titulo2.setFont(new java.awt.Font("Arial", 1, 11)); // NOI18N
        titulo2.setForeground(new java.awt.Color(0, 118, 196));
        titulo2.setText("Usted no tiene ningún certificado instalado.");

        javax.swing.GroupLayout noCertsLayout = new javax.swing.GroupLayout(noCerts);
        noCerts.setLayout(noCertsLayout);
        noCertsLayout.setHorizontalGroup(
            noCertsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(noCertsLayout.createSequentialGroup()
                .addGap(127, 127, 127)
                .addComponent(titulo2)
                .addContainerGap(119, Short.MAX_VALUE))
        );
        noCertsLayout.setVerticalGroup(
            noCertsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(noCertsLayout.createSequentialGroup()
                .addGap(72, 72, 72)
                .addComponent(titulo2)
                .addGap(83, 83, 83))
        );

        contenedor.add(noCerts);

        password.setBackground(new java.awt.Color(255, 255, 255));
        password.setMaximumSize(new java.awt.Dimension(484, 169));
        password.setMinimumSize(new java.awt.Dimension(484, 169));
        password.setPreferredSize(new java.awt.Dimension(484, 169));
        password.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        titulo1.setFont(new java.awt.Font("Arial", 1, 11)); // NOI18N
        titulo1.setForeground(new java.awt.Color(0, 118, 196));
        titulo1.setText("Ingrese la contraseña de la clave privada de su certificado.");
        password.add(titulo1, new org.netbeans.lib.awtextra.AbsoluteConstraints(80, 20, -1, -1));

        pass.setMaximumSize(new java.awt.Dimension(104, 20));
        pass.setMinimumSize(new java.awt.Dimension(104, 20));
        pass.setPreferredSize(new java.awt.Dimension(104, 20));
        pass.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                passActionPerformed(evt);
            }
        });
        password.add(pass, new org.netbeans.lib.awtextra.AbsoluteConstraints(230, 68, -1, -1));

        okButton1.setBackground(new java.awt.Color(245, 244, 244));
        okButton1.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        okButton1.setText("Aceptar");
        okButton1.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 102, 204)));
        okButton1.setMaximumSize(new java.awt.Dimension(84, 20));
        okButton1.setMinimumSize(new java.awt.Dimension(84, 20));
        okButton1.setPreferredSize(new java.awt.Dimension(84, 20));
        okButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                okButton1ActionPerformed(evt);
            }
        });
        password.add(okButton1, new org.netbeans.lib.awtextra.AbsoluteConstraints(155, 140, -1, -1));

        titulo4.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        titulo4.setForeground(new java.awt.Color(0, 118, 196));
        titulo4.setText("Contraseña:");
        password.add(titulo4, new org.netbeans.lib.awtextra.AbsoluteConstraints(160, 70, -1, -1));

        cancelar2.setBackground(new java.awt.Color(245, 244, 244));
        cancelar2.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        cancelar2.setText("Cancelar");
        cancelar2.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 102, 204)));
        cancelar2.setMaximumSize(new java.awt.Dimension(84, 20));
        cancelar2.setMinimumSize(new java.awt.Dimension(84, 20));
        cancelar2.setPreferredSize(new java.awt.Dimension(84, 20));
        cancelar2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cancelar2ActionPerformed(evt);
            }
        });
        password.add(cancelar2, new org.netbeans.lib.awtextra.AbsoluteConstraints(245, 140, -1, -1));

        contenedor.add(password);

        principal.setBackground(new java.awt.Color(255, 255, 255));
        principal.setMaximumSize(new java.awt.Dimension(484, 169));
        principal.setMinimumSize(new java.awt.Dimension(484, 169));
        principal.setPreferredSize(new java.awt.Dimension(484, 169));
        principal.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        okButton.setBackground(new java.awt.Color(245, 244, 244));
        okButton.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        okButton.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 102, 204)));
        okButton.setLabel("Exportar");
        okButton.setMaximumSize(new java.awt.Dimension(84, 20));
        okButton.setMinimumSize(new java.awt.Dimension(84, 20));
        okButton.setPreferredSize(new java.awt.Dimension(84, 20));
        okButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                okButtonActionPerformed(evt);
            }
        });
        principal.add(okButton, new org.netbeans.lib.awtextra.AbsoluteConstraints(380, 140, 84, 20));

        titulo.setFont(new java.awt.Font("Arial", 1, 11)); // NOI18N
        titulo.setForeground(new java.awt.Color(0, 118, 196));
        titulo.setText("Seleccione el certificado que desea exportar.");
        principal.add(titulo, new org.netbeans.lib.awtextra.AbsoluteConstraints(110, 20, -1, -1));

        lista.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        lista.setForeground(new java.awt.Color(0, 102, 204));
        lista.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "Nombre", "Emisor", "Fecha validez"
            }
        ));
        lista.setGridColor(new java.awt.Color(0, 102, 255));
        lista.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        lista.setShowVerticalLines(false);
        jScrollPane1.setViewportView(lista);

        principal.add(jScrollPane1, new org.netbeans.lib.awtextra.AbsoluteConstraints(16, 40, 452, 90));

        okButton5.setBackground(new java.awt.Color(245, 244, 244));
        okButton5.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        okButton5.setText("Eliminar");
        okButton5.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 102, 204)));
        okButton5.setMaximumSize(new java.awt.Dimension(84, 20));
        okButton5.setMinimumSize(new java.awt.Dimension(84, 20));
        okButton5.setPreferredSize(new java.awt.Dimension(84, 20));
        okButton5.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                okButton5ActionPerformed(evt);
            }
        });
        principal.add(okButton5, new org.netbeans.lib.awtextra.AbsoluteConstraints(290, 140, 84, 20));

        contenedor.add(principal);

        hayError.setBackground(new java.awt.Color(255, 255, 255));
        hayError.setMaximumSize(new java.awt.Dimension(484, 169));
        hayError.setMinimumSize(new java.awt.Dimension(484, 169));
        hayError.setPreferredSize(new java.awt.Dimension(484, 169));

        titulo8.setFont(new java.awt.Font("Arial", 1, 11)); // NOI18N
        titulo8.setForeground(new java.awt.Color(255, 0, 51));
        titulo8.setText("Ha ocurrido un error y no se ha podido exportar el certificado.");

        okButton3.setBackground(new java.awt.Color(245, 244, 244));
        okButton3.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        okButton3.setText("Aceptar");
        okButton3.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 102, 204)));
        okButton3.setMaximumSize(new java.awt.Dimension(84, 20));
        okButton3.setMinimumSize(new java.awt.Dimension(84, 20));
        okButton3.setPreferredSize(new java.awt.Dimension(84, 20));
        okButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                okButton3ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout hayErrorLayout = new javax.swing.GroupLayout(hayError);
        hayError.setLayout(hayErrorLayout);
        hayErrorLayout.setHorizontalGroup(
            hayErrorLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(hayErrorLayout.createSequentialGroup()
                .addGap(80, 80, 80)
                .addComponent(titulo8)
                .addGap(65, 65, 65))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, hayErrorLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(okButton3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(198, 198, 198))
        );
        hayErrorLayout.setVerticalGroup(
            hayErrorLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(hayErrorLayout.createSequentialGroup()
                .addGap(70, 70, 70)
                .addComponent(titulo8)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 54, Short.MAX_VALUE)
                .addComponent(okButton3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        contenedor.add(hayError);

        finalizar2.setBackground(new java.awt.Color(255, 255, 255));
        finalizar2.setMaximumSize(new java.awt.Dimension(484, 169));
        finalizar2.setMinimumSize(new java.awt.Dimension(484, 169));

        titulo9.setFont(new java.awt.Font("Arial", 1, 11)); // NOI18N
        titulo9.setForeground(new java.awt.Color(0, 118, 196));
        titulo9.setText("Se ha eliminado correctamente el certificado.");

        okButton7.setBackground(new java.awt.Color(245, 244, 244));
        okButton7.setFont(new java.awt.Font("Arial", 0, 11)); // NOI18N
        okButton7.setText("Aceptar");
        okButton7.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 102, 204)));
        okButton7.setMaximumSize(new java.awt.Dimension(84, 20));
        okButton7.setMinimumSize(new java.awt.Dimension(84, 20));
        okButton7.setPreferredSize(new java.awt.Dimension(84, 20));
        okButton7.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                okButton7ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout finalizar2Layout = new javax.swing.GroupLayout(finalizar2);
        finalizar2.setLayout(finalizar2Layout);
        finalizar2Layout.setHorizontalGroup(
            finalizar2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(finalizar2Layout.createSequentialGroup()
                .addGroup(finalizar2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(finalizar2Layout.createSequentialGroup()
                        .addGap(122, 122, 122)
                        .addComponent(titulo9))
                    .addGroup(finalizar2Layout.createSequentialGroup()
                        .addGap(202, 202, 202)
                        .addComponent(okButton7, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(121, Short.MAX_VALUE))
        );
        finalizar2Layout.setVerticalGroup(
            finalizar2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(finalizar2Layout.createSequentialGroup()
                .addGap(74, 74, 74)
                .addComponent(titulo9)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 50, Short.MAX_VALUE)
                .addComponent(okButton7, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        contenedor.add(finalizar2);

        getContentPane().add(contenedor);
    }// </editor-fold>//GEN-END:initComponents

    //Acción del botón aceptar luego de seleccionar un certificado
    private void okButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_okButtonActionPerformed
        //Obtengo el certificado seleccionado.
        eliminar = false;
        //seleccionado = lista.getModel().getValueAt(lista.getSelectedRow(), 0)+" - "+lista.getModel().getValueAt(lista.getSelectedRow(), 1)+" - "+lista.getModel().getValueAt(lista.getSelectedRow(), 2);
        seleccionado = String.valueOf(lista.getSelectedRow());
        //muestro el panel para ingresar la contraseña.
        principal.setVisible(false);
        noCerts.setVisible(false);
        password.setVisible(true);
        finalizar.setVisible(false);
        passwordError.setVisible(false);
        hayError.setVisible(false);
        finalizar2.setVisible(false);
}//GEN-LAST:event_okButtonActionPerformed

    //Acción del botón aceptar luego de ingresar la contraseña
    private void okButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_okButton1ActionPerformed
        contra = pass.getPassword();
        if(eliminar){
            eliminarCertificado();
        }else{
            exportarCertificado();
        }
        if(error==1){
            //Ingresé el password incorrecto. Muestro el panel que informa y permite reingresarlo.
            principal.setVisible(false);
            noCerts.setVisible(false);
            password.setVisible(false);
            passwordError.setVisible(true);
            finalizar.setVisible(false);
            hayError.setVisible(false);
            finalizar2.setVisible(false);
        }else if(error==2){
            //Hubo error. Muestro el panel que informa.
            principal.setVisible(false);
            noCerts.setVisible(false);
            password.setVisible(false);
            finalizar.setVisible(false);
            passwordError.setVisible(false);
            hayError.setVisible(true);
            finalizar2.setVisible(false);
        }else if(error != 3){
            //Se exportó correctamente. Muestro el panel que informa.
            principal.setVisible(false);
            noCerts.setVisible(false);
            password.setVisible(false);
            if(eliminar){
                finalizar.setVisible(false);
                finalizar2.setVisible(true);
            }else{
                finalizar.setVisible(true);
                finalizar2.setVisible(false);
            }
            passwordError.setVisible(false);
            hayError.setVisible(false);
        }
}//GEN-LAST:event_okButton1ActionPerformed

    //Acción del botón aceptar luego de ingresar la contraseña nuevamente
    private void okButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_okButton2ActionPerformed
        contra = pass1.getPassword();
        if(eliminar){
            eliminarCertificado();
        }else{
            exportarCertificado();
        }
        if(error==1){
            //Ingresé el password incorrecto. Muestro el panel que informa y permite reingresarlo.
            principal.setVisible(false);
            noCerts.setVisible(false);
            password.setVisible(false);
            passwordError.setVisible(true);
            finalizar.setVisible(false);
            hayError.setVisible(false);
            finalizar2.setVisible(false);
        }else if(error==2){
            //Hubo error. Muestro el panel que informa.
            principal.setVisible(false);
            noCerts.setVisible(false);
            password.setVisible(false);
            finalizar.setVisible(false);
            passwordError.setVisible(false);
            hayError.setVisible(true);
            finalizar2.setVisible(false);
        }else if(error != 3){
            //Se exportó correctamente. Muestro el panel que informa.
            principal.setVisible(false);
            noCerts.setVisible(false);
            password.setVisible(false);
            if(eliminar){
                finalizar.setVisible(false);
                finalizar2.setVisible(true);
            }else{
                finalizar.setVisible(true);
                finalizar2.setVisible(false);
            }
            passwordError.setVisible(false);
            hayError.setVisible(false);
        }
    }//GEN-LAST:event_okButton2ActionPerformed

    //Botón cancelar
    private void cancelarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cancelarActionPerformed
        lista.removeAll();
        init();
}//GEN-LAST:event_cancelarActionPerformed

    //Botón cancelar
    private void cancelar2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cancelar2ActionPerformed
        lista.removeAll();
        init();
}//GEN-LAST:event_cancelar2ActionPerformed

    private void passActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_passActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_passActionPerformed

    //Botón Ok
    private void okButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_okButton3ActionPerformed
        lista.removeAll();
        init();
    }//GEN-LAST:event_okButton3ActionPerformed

    private void okButton5ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_okButton5ActionPerformed
        //Obtengo el certificado seleccionado.
        //seleccionado = lista.getModel().getValueAt(lista.getSelectedRow(), 0)+" - "+lista.getModel().getValueAt(lista.getSelectedRow(), 1)+" - "+lista.getModel().getValueAt(lista.getSelectedRow(), 2);
        seleccionado = String.valueOf(lista.getSelectedRow());
        //muestro el panel para ingresar la contraseña.
        eliminar = true;
        principal.setVisible(false);
        noCerts.setVisible(false);
        password.setVisible(true);
        finalizar.setVisible(false);
        passwordError.setVisible(false);
        hayError.setVisible(false);
        finalizar2.setVisible(false);
    }//GEN-LAST:event_okButton5ActionPerformed

    private void okButton6ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_okButton6ActionPerformed
        lista.removeAll();
        init();
    }//GEN-LAST:event_okButton6ActionPerformed

    private void okButton7ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_okButton7ActionPerformed
        lista.removeAll();
        init();
    }//GEN-LAST:event_okButton7ActionPerformed

    private void exportarCertificado(){
        error=1;
        String alias = (String) aliasHash.get(seleccionado);
        X509Certificate certificado =  (X509Certificate) certs.get(seleccionado);
        
        PrivateKey ky;
        try {
            Certificate[] certChain = (Certificate[]) keystore.getCertificateChain(alias);
            ky = (PrivateKey) keystore.getKey(alias, contra);
            if(guardarCertificado(ky, certificado, certChain, contra))
                error = 0;
            else
                error = 3;
        } catch (KeyStoreException ex) {
            Logger.getLogger(ExportApplet.class.getName()).log(Level.SEVERE, null, ex);
            error=2;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ExportApplet.class.getName()).log(Level.SEVERE, null, ex);
            error=2;
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(ExportApplet.class.getName()).log(Level.SEVERE, null, ex);
            error=1;
        } catch (Exception ex) {
            Logger.getLogger(ExportApplet.class.getName()).log(Level.SEVERE, null, ex);
            error=2;
        }

    }
    
    private boolean guardarCertificado(PrivateKey privada, X509Certificate certFirmado, Certificate[] certChain,char[] pass) throws KeyStoreException, NoSuchProviderException, IOException, NoSuchAlgorithmException, CertificateException {
        JFileChooser chooser = new JFileChooser();
        int status = chooser.showSaveDialog(password);
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
                keyS.setKeyEntry(certFirmado.getSerialNumber().toString(), privada, pass, certChain);
                FileOutputStream out = new FileOutputStream(savePath+".pfx");
                keyS.store(out, pass);
                out.close();
                return true;
            }else{
                int answer = JOptionPane.showConfirmDialog(password, "Ya existe un archivo con ese nombre. ¿Desea reemplazarlo?","Descarga",JOptionPane.YES_NO_OPTION);
                if (answer == JOptionPane.YES_OPTION) {
                    KeyStore keyS = KeyStore.getInstance("PKCS12");
                    keyS.load(null,null);
                    //keyS.setCertificateEntry(certFirmado.getSerialNumber().toString(), certFirmado);
                    keyS.setKeyEntry(certFirmado.getSerialNumber().toString(), privada, pass, certChain);
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
    
    private void eliminarCertificado(){
        error=1;
        String alias = (String) aliasHash.get(seleccionado);
        try {
            PrivateKey ky = (PrivateKey) keystore.getKey(alias, contra);
            keystore.deleteEntry(alias);
            String keystoreFilename;
            if(isOSWindows()){
                keystoreFilename = System.getenv("APPDATA").replace("\\", "/")+"/IGDoc/almacenIGDOC";
            }else{
                keystoreFilename = System.getProperty("user.home").replace("\\", "/")+"/.IGDoc/almacenIGDOC";
            }
            FileOutputStream out = new FileOutputStream(keystoreFilename);
            keystore.store(out, "default".toCharArray());
            out.close();
            error=0;
        } catch (KeyStoreException ex) {
            Logger.getLogger(ExportApplet.class.getName()).log(Level.SEVERE, null, ex);
            error=2;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ExportApplet.class.getName()).log(Level.SEVERE, null, ex);
            error=2;
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(ExportApplet.class.getName()).log(Level.SEVERE, null, ex);
            error=1;
        } catch (Exception ex) {
            Logger.getLogger(ExportApplet.class.getName()).log(Level.SEVERE, null, ex);
            error=2;
        }
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton cancelar;
    private javax.swing.JButton cancelar2;
    private javax.swing.JPanel contenedor;
    private javax.swing.JPanel finalizar;
    private javax.swing.JPanel finalizar2;
    private javax.swing.JPanel hayError;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTable lista;
    private javax.swing.JPanel noCerts;
    private javax.swing.JButton okButton;
    private javax.swing.JButton okButton1;
    private javax.swing.JButton okButton2;
    private javax.swing.JButton okButton3;
    private javax.swing.JButton okButton5;
    private javax.swing.JButton okButton6;
    private javax.swing.JButton okButton7;
    private javax.swing.JPasswordField pass;
    private javax.swing.JPasswordField pass1;
    private javax.swing.JPanel password;
    private javax.swing.JPanel passwordError;
    private javax.swing.JPanel principal;
    private javax.swing.JLabel titulo;
    private javax.swing.JLabel titulo1;
    private javax.swing.JLabel titulo2;
    private javax.swing.JLabel titulo3;
    private javax.swing.JLabel titulo4;
    private javax.swing.JLabel titulo5;
    private javax.swing.JLabel titulo6;
    private javax.swing.JLabel titulo7;
    private javax.swing.JLabel titulo8;
    private javax.swing.JLabel titulo9;
    // End of variables declaration//GEN-END:variables

}
