/* Copyright 2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package wslite.http

import javax.net.ssl.*

import java.net.Proxy;
import java.security.KeyStore
import java.security.SecureRandom

class HTTPConnectionFactory {

	/**
	 * Which protocol to use for secure connections (e.g.: SSL, TLSv1, TLSv1.2, ...). Default TLSv1
	 */
	String securityProtocol = "TLSv1"
	
	def getSecureConnection(URL url, Proxy proxy=Proxy.NO_PROXY) {		
		SSLContext sc = SSLContext.getInstance(securityProtocol)
		sc.init(null, null, null) // use default

		HttpsURLConnection httpsCon = (HttpsURLConnection) url.openConnection()
		httpsCon.setSSLSocketFactory(sc.getSocketFactory())
		
		return httpsCon
	}
	
    def getConnection(URL url, Proxy proxy=Proxy.NO_PROXY) {
        return url.openConnection(proxy)
    }

    def getConnectionTrustAllSSLCerts(URL url, Proxy proxy=Proxy.NO_PROXY) {
        def trustingTrustManager = [
                getAcceptedIssuers: {},
                checkClientTrusted: { arg0, arg1 -> },
                checkServerTrusted: {arg0, arg1 -> }
        ] as X509TrustManager
        SSLContext sc = SSLContext.getInstance(securityProtocol)
        sc.init(null, [trustingTrustManager] as TrustManager[], null)
        def conn = getConnection(url, proxy)
        conn.setSSLSocketFactory(sc.getSocketFactory())
        conn.setHostnameVerifier({arg0, arg1 -> return true} as HostnameVerifier)
        return conn
    }

    def getConnectionUsingTrustStore(URL url, String trustStoreFile, String trustStorePassword,
                                     Proxy proxy=Proxy.NO_PROXY) {
        InputStream tsFile = new FileInputStream(new File(trustStoreFile))
        char[] tsPassword = trustStorePassword?.getChars()

        def keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
        keyStore.load(tsFile, tsPassword)

        def kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(keyStore, tsPassword)

        def tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(keyStore)

        def sc = SSLContext.getInstance(securityProtocol)
        sc.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom())

        def conn = getConnection(url, proxy)
        conn.setSSLSocketFactory(sc.getSocketFactory())

        return conn
    }

}
