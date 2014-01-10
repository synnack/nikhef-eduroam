/* Copyright 2013 Wilco Baan Hofman <wilco@baanhofman.nl>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package nl.nikhef.eduroam;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import android.provider.Settings.Secure;
import android.security.KeyChain;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.UnknownHostException;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.bouncycastle.util.encoders.Base64;
import org.json.JSONException;
import org.json.JSONObject;
import nl.nikhef.eduroam.R;


import android.annotation.TargetApi;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.AlertDialog.Builder;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiEnterpriseConfig.Phase2;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

// API level 18 and up
import android.net.wifi.WifiEnterpriseConfig;
import android.net.wifi.WifiEnterpriseConfig.Eap;

public class WiFiEduroam extends Activity {
	// FIXME This should be a configuration setting somehow
	private static final String CONF_HTTP_URL = "https://mobi.nikhef.nl/provision/";
	
	private static final String INT_EAP = "eap";
	private static final String INT_ENGINE = "engine";
	private static final String INT_ENGINE_ID = "engine_id";
	private static final String INT_CLIENT_CERT = "client_cert";
	private static final String INT_CA_CERT = "ca_cert";
	private static final String INT_PRIVATE_KEY = "private_key";
	private static final String INT_PRIVATE_KEY_ID = "key_id";
	private static final String INT_SUBJECT_MATCH = "subject_match";
	private static final String INT_ANONYMOUS_IDENTITY = "anonymous_identity";
	private static final String INT_ENTERPRISEFIELD_NAME = "android.net.wifi.WifiConfiguration$EnterpriseField";
	
	// Because android.security.Credentials cannot be resolved...
	private static final String INT_KEYSTORE_URI = "keystore://";
	private static final String INT_CA_PREFIX = INT_KEYSTORE_URI + "CACERT_";
	private static final String INT_PRIVATE_KEY_PREFIX = INT_KEYSTORE_URI + "USRPKEY_";
	private static final String INT_PRIVATE_KEY_ID_PREFIX = "USRPKEY_";
	private static final String INT_CLIENT_CERT_PREFIX = INT_KEYSTORE_URI + "USRCERT_";
	
	private static final String INT_CLIENT_CERT_NAME = "client certificate";

	protected static final int SHOW_PREFERENCES = 0;
	protected static AlertDialog alertDialog;
	private CSR csr;
    private Handler mHandler = new Handler();
	private EditText username;
	private EditText password;
	private String certificate;
	private String ca;
	private String ca_name;
	private String client_cert_name;
	private String subject_match;
	private String realm;
	private String ssid;
	private boolean busy = false;
	private Toast toast = null;
	
	// Called when the activity is first created.
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);  
		setContentView(R.layout.logon);
		
		username = (EditText) findViewById(R.id.username);
		password = (EditText) findViewById(R.id.password);
		
		alertDialog = new AlertDialog.Builder(this).create();
		
		Button myButton = (Button) findViewById(R.id.button1);
		if (myButton == null)
			throw new RuntimeException("button1 not found. Odd");
		
		
		myButton.setOnClickListener(new Button.OnClickListener() {
			public void onClick(View _v) {
				if (busy) {
					return;
				}
				busy = true;
				// Most of this stuff runs in the background
				Thread t = new Thread() {
					@Override
					public void run() {
						try {
							if (csr == null) {
								updateStatus("Generating certificate signing request... This may take a while");
								csr = new CSR(username.getText().toString() + "@nikhef.nl");
							}
							
							updateStatus("Sending CSR to the server...");
							postData(username.getText().toString(), password.getText().toString(), csr.getCSR());
							
							updateStatus("Installing WiFi profile...");
							if (android.os.Build.VERSION.SDK_INT >= 11 && android.os.Build.VERSION.SDK_INT <= 17) {
								installCertificates();
							} else if (android.os.Build.VERSION.SDK_INT >= 18) {
								saveWifiConfig();
								updateStatus("All done!");
								// Clear the password field in the UI thread
								mHandler.post(new Runnable() {
									@Override
									public void run() {
										password.setText("");
									};
								});

							} else {
								throw new RuntimeException("What version is this?! API Mismatch");
							}
						} catch (RuntimeException e) {
							updateStatus("Runtime Error: " + e.getMessage());
							e.printStackTrace();
						} catch (Exception e) {
							e.printStackTrace();
						}
						busy = false;
					}
				};
				t.start();
				
			}
		});

	}

	private void saveWifiConfig() {
		WifiManager wifiManager = (WifiManager) this.getSystemService(WIFI_SERVICE);
		wifiManager.setWifiEnabled(true);
		
		WifiConfiguration currentConfig = new WifiConfiguration();
		
		List<WifiConfiguration> configs = null;
		for (int i = 0; i < 10 && configs == null; i++) {
			configs = wifiManager.getConfiguredNetworks();
			try {
				Thread.sleep(1);
			}
			catch(InterruptedException e) {
				continue;			
			}
		}

		// Use the existing eduroam profile if it exists.
		boolean ssidExists = false;
		if (configs != null) {
			for (WifiConfiguration config : configs) {
				if (config.SSID.equals(surroundWithQuotes(ssid))) {
					currentConfig = config;
					ssidExists = true;
					break;
				}
			}
		}
		
		currentConfig.SSID = surroundWithQuotes(ssid);
		currentConfig.hiddenSSID = false;
		currentConfig.priority = 40;
		currentConfig.status = WifiConfiguration.Status.DISABLED;
		
		currentConfig.allowedKeyManagement.clear();
		currentConfig.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_EAP);

		// GroupCiphers (Allow most ciphers)
		currentConfig.allowedGroupCiphers.clear();
		currentConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
		currentConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
		currentConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP104);

		
		// PairwiseCiphers (CCMP = WPA2 only)
		currentConfig.allowedPairwiseCiphers.clear();
		currentConfig.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);

		// Authentication Algorithms (OPEN)
		currentConfig.allowedAuthAlgorithms.clear();
		currentConfig.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN);

		// Protocols (RSN/WPA2 only)
		currentConfig.allowedProtocols.clear();
		currentConfig.allowedProtocols.set(WifiConfiguration.Protocol.RSN);

		// Enterprise Settings
		HashMap<String,String> configMap = new HashMap<String,String>();
		configMap.put(INT_SUBJECT_MATCH, subject_match);
		configMap.put(INT_ANONYMOUS_IDENTITY, "anonymous" + realm);
		configMap.put(INT_EAP, "TLS");
		configMap.put(INT_ENGINE, "1");
		configMap.put(INT_ENGINE_ID, "keystore");
		configMap.put(INT_CA_CERT, INT_CA_PREFIX + ca_name);
		configMap.put(INT_PRIVATE_KEY, INT_PRIVATE_KEY_PREFIX + client_cert_name);
		configMap.put(INT_PRIVATE_KEY_ID, INT_PRIVATE_KEY_ID_PREFIX + client_cert_name);
		configMap.put(INT_CLIENT_CERT, INT_CLIENT_CERT_PREFIX + client_cert_name);

		if (android.os.Build.VERSION.SDK_INT >= 11 && android.os.Build.VERSION.SDK_INT <= 17) {
			applyAndroid4_42EnterpriseSettings(currentConfig, configMap);
		} else if (android.os.Build.VERSION.SDK_INT >= 18) {
			applyAndroid43EnterpriseSettings(currentConfig, configMap);
		} else {
			throw new RuntimeException("API version mismatch!");
		}
		
		if (!ssidExists) {
			int networkId = wifiManager.addNetwork(currentConfig);
			wifiManager.enableNetwork(networkId, false);
		} else {
			wifiManager.updateNetwork(currentConfig);
			wifiManager.enableNetwork(currentConfig.networkId, false);
		}
		wifiManager.saveConfiguration();
		
	}


	@TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
	private void applyAndroid43EnterpriseSettings(WifiConfiguration currentConfig, HashMap<String,String> configMap) {
		try {
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			InputStream in = new ByteArrayInputStream(Base64.decode(certificate.replaceAll("-----(BEGIN|END) CERTIFICATE-----", "")));
			X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);
			in = new ByteArrayInputStream(Base64.decode(ca.replaceAll("-----(BEGIN|END) CERTIFICATE-----", "")));
			X509Certificate caCert = (X509Certificate) certFactory.generateCertificate(in);
		
			WifiEnterpriseConfig enterpriseConfig = new WifiEnterpriseConfig();
			enterpriseConfig.setPhase2Method(Phase2.NONE);
			enterpriseConfig.setAnonymousIdentity(configMap.get(INT_ANONYMOUS_IDENTITY));
			enterpriseConfig.setEapMethod(Eap.TLS);
	
			enterpriseConfig.setCaCertificate(caCert);
			enterpriseConfig.setClientKeyEntry(this.csr.getPrivate(), cert);
			enterpriseConfig.setIdentity(configMap.get(INT_ANONYMOUS_IDENTITY));
			enterpriseConfig.setSubjectMatch(configMap.get(INT_SUBJECT_MATCH));
			currentConfig.enterpriseConfig = enterpriseConfig;
			
		} catch(Exception e) {
			e.printStackTrace();
		}
	}

	@TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
	// Step 1 for android 4.0 - 4.2
	private void installCertificates() {
		// Install the CA certificate
		updateStatus("Inputting CA certificate.");
		Intent intent = KeyChain.createInstallIntent();
		intent.putExtra(KeyChain.EXTRA_NAME, ca_name);
		intent.putExtra(KeyChain.EXTRA_CERTIFICATE, Base64.decode(ca.replaceAll("-----(BEGIN|END) CERTIFICATE-----", "")));
		startActivityForResult(intent, 1);
		
	}


	@Override
	@TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
	// Step 2 for android 4.0 - 4.2; dispatcher for later steps
	public void onActivityResult(int requestCode, int resultCode, Intent intent) {
		if (resultCode != RESULT_OK) {
			updateStatus("Aborted.");
			return;
		}
		if (requestCode == 1) {
			alert("Password", "In the next dialog, type \"" + ssid + "\" as the password.");
			return;
		}
		
		if (requestCode == 2) {
			installClientCertificate();
			return;
		}
		
		
		if (requestCode == 3) {
			saveWifiConfig();
			updateStatus("All done!");
			password.setText("");
			return;
		}
		
	}
	
	@TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
	// Step 3 for android 4.0 - 4.2
	private void installClientCertificate() {
		try {
			updateStatus("Inputting client certificate.");
			
			// Parse the certificate that we got from the server
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			InputStream in = new ByteArrayInputStream(Base64.decode(certificate.replaceAll("-----(BEGIN|END) CERTIFICATE-----", "")));
			X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);
			
			
			client_cert_name = ssid + " " + INT_CLIENT_CERT_NAME;
			
			// Create a pkcs12 certificate/private key combination
			Security.addProvider(new BouncyCastleProvider());
			KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
			keystore.load(null, null);
			Certificate chain[] = new Certificate[] {(Certificate)cert}; 
			keystore.setKeyEntry(client_cert_name, csr.getPrivate(), null, chain);
			
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			keystore.store(out, ssid.toCharArray());
			out.flush();
			byte[] buffer = out.toByteArray();
			out.close();
			
			// Install the private key/client certificate combination
			Intent intent = KeyChain.createInstallIntent();
			intent.putExtra(KeyChain.EXTRA_NAME, ssid + " " + INT_CLIENT_CERT_NAME);
			intent.putExtra(KeyChain.EXTRA_PKCS12, buffer);
			startActivityForResult(intent, 3);
		} catch (CertificateException e) {
			e.printStackTrace();
			throw new RuntimeException("Certificate error.");
		} catch (KeyStoreException e) {
			e.printStackTrace();
			System.out.println(e.getMessage());
			throw new RuntimeException("Certificate error: KeyStore");
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			throw new RuntimeException("Certificate error: Provider");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new RuntimeException("Certificate error: Algorithm");
		} catch (IOException e) {
			e.printStackTrace();
			throw new RuntimeException("Certificate error: IO");
		}
	}
	

	
	
	@TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
	// Last step for android 4.0 - 4.2, called from saveWifiConfig
	private void applyAndroid4_42EnterpriseSettings(WifiConfiguration currentConfig, HashMap<String,String> configMap){
		// NOTE: This code is mighty ugly, but reflection is the only way to get the methods we need
		// Get the enterprise class via reflection
		Class<?>[] wcClasses = WifiConfiguration.class.getClasses();
		Class<?> wcEnterpriseField = null;

		for (Class<?> wcClass : wcClasses) {
			if (wcClass.getName().equals(
					INT_ENTERPRISEFIELD_NAME)) {
				wcEnterpriseField = wcClass;
				break;
			}
		}
		if (wcEnterpriseField == null) {
			throw new RuntimeException("There is no enterprisefield class.");
		}
		
		// Get the setValue handler via reflection
		Method wcefSetValue = null;
		for (Method m: wcEnterpriseField.getMethods()) {
			if(m.getName().equals("setValue")) {
				wcefSetValue = m;
				break;
			}
		}
		if(wcefSetValue == null) {
			throw new RuntimeException("There is no setValue method.");
		}
		
		// Fill fields from the HashMap
		Field[] wcefFields = WifiConfiguration.class.getFields();
		for (Field wcefField : wcefFields) {
			if (configMap.containsKey(wcefField.getName())) {
				try {
					wcefSetValue.invoke(wcefField.get(currentConfig), 
							configMap.get(wcefField.getName()));
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		MenuInflater inflater = getMenuInflater();
		inflater.inflate(R.menu.options_menu, menu);
		return true;
	}
	
	@Override
	public boolean onOptionsItemSelected(MenuItem item){
		Builder builder = new AlertDialog.Builder(this);
		switch (item.getItemId()) {
	    case R.id.about:
	    	PackageInfo pi = null;
	    	try{
	    		pi = getPackageManager().getPackageInfo(getClass().getPackage().getName(), 0);
	    	} catch(Exception e){
	    		e.printStackTrace();
	    	}
	    	builder.setTitle(getString(R.string.ABOUT_TITLE));
	    	builder.setMessage(getString(R.string.ABOUT_CONTENT)+
					"\n\n"+pi.packageName+"\n"+
					"V"+pi.versionName+
					"C"+pi.versionCode);
			builder.setPositiveButton(getString(android.R.string.ok), null);
			builder.show();
	    	
	        return true;
	    case R.id.exit:
	    	System.exit(0);
	    }
	    return false;
	}

	
	
	// This function does the HTTP POST request for provisioning and parses the JSON response
		private void postData(String username, String password, String csr) throws RuntimeException {
		    // Create a new HttpClient and Post Header
		    HttpClient httpclient = new DefaultHttpClient();
		    HttpPost httppost = new HttpPost(CONF_HTTP_URL);


		    String android_id = Secure.getString(getBaseContext().getContentResolver(),
		                                                            Secure.ANDROID_ID);
		    
		    
		    try {
		        // Add the post data
		        List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>(2);
		        nameValuePairs.add(new BasicNameValuePair("username", username));
		        nameValuePairs.add(new BasicNameValuePair("password", password));
		        nameValuePairs.add(new BasicNameValuePair("csr", csr));
		        nameValuePairs.add(new BasicNameValuePair("device_id", android_id));
		        nameValuePairs.add(new BasicNameValuePair("device_serial", android.os.Build.SERIAL));
		        nameValuePairs.add(new BasicNameValuePair("device_description", android.os.Build.MANUFACTURER + " " + 
		                                                                        android.os.Build.MODEL + " / " +
		        		                                                        android.os.Build.PRODUCT));
		        httppost.setEntity(new UrlEncodedFormEntity(nameValuePairs));

		        // Execute HTTP POST request synchronously
		        HttpResponse response = httpclient.execute(httppost);
		        if (!response.getStatusLine().toString().endsWith("200 OK")) {
		        	updateStatus("HTTP Error: " + response.getStatusLine());
		        }
		     
		        // Convert input to JSON object
		        BufferedReader reader = new BufferedReader(new InputStreamReader(response.getEntity().getContent(), "UTF-8"));
		        StringBuilder builder = new StringBuilder();
		        for (String line = null; (line = reader.readLine()) != null;) {
		            builder.append(line).append("\n");
		        }
		        String json = builder.toString();
		        JSONObject obj = new JSONObject(json);
		        
	            if (!obj.getString("status").equals("ok")) {
	            	updateStatus("JSON Status Error: " + obj.getString("error"));
	            	throw new RuntimeException(obj.getString("error"));
	            }
	            // Grab the information
	            certificate = obj.getString("certificate");
	            ca = obj.getString("ca");
	            ca_name = obj.getString("ca_name");
	            realm = obj.getString("realm");
	            subject_match = obj.getString("subject_match");
	            ssid = obj.getString("ssid");
		    } catch (ClientProtocolException e) {
				e.printStackTrace();
		    } catch (UnknownHostException e) {
				e.printStackTrace();
				throw new RuntimeException("Please check your connection!");
		    } catch (IOException e) {
				e.printStackTrace();
		    } catch (JSONException e) {
		    	throw new RuntimeException("JSON: " + e.getMessage());
		    }
		} 
		
	
	
	/* Update the status in the main thread */
	protected void updateStatus(final String text) {
		mHandler.post(new Runnable() {
			@Override
			public void run() {
				System.out.println(text);
				if (toast != null)
					toast.cancel();
				toast = Toast.makeText(getBaseContext(), text, Toast.LENGTH_LONG);
				toast.show();
			};
		});
	}
	

	
	private void alert(String title, String message) {
		AlertDialog alertBox = new AlertDialog.Builder(this).create();
		alertBox.setTitle(title);
		alertBox.setMessage(message);
		alertBox.setButton(AlertDialog.BUTTON_POSITIVE, "OK", new DialogInterface.OnClickListener(){

			@Override
			public void onClick(DialogInterface dialog, int which) {               
				onActivityResult(2, RESULT_OK, null);
			}
		});
		alertBox.show();
	}
		
	
	static String removeQuotes(String str) {
		int len = str.length();
		if ((len > 1) && (str.charAt(0) == '"') && (str.charAt(len - 1) == '"')) {
			return str.substring(1, len - 1);
		}
		return str;
	}

	static String surroundWithQuotes(String string) {
		return "\"" + string + "\"";
	}
}