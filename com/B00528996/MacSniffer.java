package com.B00528996;

import java.applet.Applet;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Collections;
import netscape.javascript.JSObject;

/*
 *  MacSniffer applet
 *  Author: Dave Armstrong
 *  Student No: B00528996
 *  
 *  Description:
 *  An applet that will return the highest signal strength
 *  BSSID detected from a Window 7 laptop or
 *  The BSSID of the connected Access Point of a Mac OSX
 *  laptop
 * 
 * 
 */

public class MacSniffer extends Applet {

    // need to know the OS so we can conditionally change the parsing of netstat
    String OS = System.getProperty("os.name");
    JSObject win;

    @Override
    public void init(){
         // get the browser window
          win = JSObject.getWindow(this);

         // get the mac string
         // use doPrivileged to up the permission of javascript
         AccessController.doPrivileged(new PrivilegedAction() {
           public Object run() {
                try {
                    // run the appropriate lookup functions based on the OS
                    if (OS.equals("Windows 7")){
                        runWindowsLookup();
                    } else if (OS.equals("Mac OS X")){
                        runOSXLookup();
                    } else {
                        MacSniffer.this.win.eval("displayMac('-1')"); //unsupported operating system
                    }
                 } catch (IOException ex) {
                      MacSniffer.this.win.eval("displayMac('0')"); //failed to run lookup
                 }

                // return true if everything executed as expected
                return true;
           }
           
           private void runWindowsLookup() throws IOException{
               
               BufferedReader br = null;
               String thisLine = null;
               
                // read all the wireless networks
                Process netshOut = Runtime.getRuntime().exec("netsh wlan show networks mode=BSSID");
                // we need to parse this information to get the gateway BSSID
                br = new BufferedReader(new InputStreamReader(netshOut.getInputStream()));
                
                if(br != null){
                    // we have run the lookup and have the result returned to us
                    // we need to loop through the results and store the parts we want
                    
                    // unlike the previous sniffer we are basing the location on the 
                    // strength of signal picked up by the WIFI adapter and not the gateway
                    // of the current connection
                    
                    ArrayList<AccessPoint> matches = new ArrayList();
                    
                    while((thisLine = br.readLine()) != null){
                        
                        if(thisLine.startsWith("SSID")){
                            
                            AccessPoint ap = new AccessPoint();
                            
                            String[] ssid = thisLine.split(": ");
                            ap.set_ssid(ssid[1].trim());
                            
                            br.readLine(); // skip to the next 3 lines
                            br.readLine();
                            br.readLine();
                            
                            String[] bssid = br.readLine().split(": ");
                            ap.set_bssid(bssid[1].trim());
                            // signal strenth line is found, so ditch the label, remove the percentage symbol and convert to integer
                            String[] ss = br.readLine().split(": ");
                            ap.set_signal_strength(Integer.parseInt(ss[1].trim().replace("%", "")));
                            
                            matches.add(ap);
                        }
                        
                    }
                    // sort the matches - this is based on signal strength
                    Collections.sort(matches);
                    // return the bssid of the top match
                    if(matches.size() > 0){
                        MacSniffer.this.win.eval("displayMac('" + matches.get(0).get_bssid() +"')");
                    } else {
                        // if we have gotten this far then there are no APs or the device does not have WIFI
                        MacSniffer.this.win.eval("displayMac('1')");
                    }
                    
                    
                    
                }
                
           }

            private void runOSXLookup() throws IOException{
               
               BufferedReader br = null;
               String thisLine = null;
               Boolean found = false;
               
                // read all the wireless networks
                Process netshOut = Runtime.getRuntime().exec("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I");
                // we need to parse this information to get the gateway BSSID
                br = new BufferedReader(new InputStreamReader(netshOut.getInputStream()));
                
                
                if(br != null){
                    // loop through each line of the output
                    while((thisLine = br.readLine()) != null){
                        
                        // remove the excess spacing
                        String compressedLine = thisLine.replaceAll("( )+", " ").trim();
                        
                        // look for the line containing the connected WIFI BSSID
                        if(compressedLine.startsWith("BSSID")){
                            String[] bssid = thisLine.split(": ");
                            MacSniffer.this.win.eval("displayMac('" + bssid[1].trim() + "')");
                            found = true;
                        }
                        
                    }
                    
                    if(!found){
                       MacSniffer.this.win.eval("displayMac('1')");
                    }
                    
                }
                
            }

           
            
            
         });
        

    }

    @Override
    public void stop(){
        // do nothing
    }
    
    // AccessPoint Object
    // Allows our list of found access points to be stored and compared based upon the signal strength
    private static class AccessPoint implements Comparable<AccessPoint> {
            
        private String ssid;
        private String bssid;
        private int signal_strength;
        
        public AccessPoint() {
            
        }

        public String get_bssid() {
            return bssid;
        }

        public void set_bssid(String bssid) {
            this.bssid = bssid;
        }

        public int get_signal_strength() {
            return signal_strength;
        }

        public void set_signal_strength(int signal_strength) {
            this.signal_strength = signal_strength;
        }

        public String get_ssid() {
            return ssid;
        }

        public void set_ssid(String ssid) {
            this.ssid = ssid;
        }

        @Override
        public int compareTo(AccessPoint ap) {
           
           if(this.get_signal_strength() < ap.get_signal_strength()){
               return 1;
           } else if(this.get_signal_strength() > ap.get_signal_strength()){
               return -1;
           } else {
               return 0;
           }
            
        }
        
        
    }
    
}
