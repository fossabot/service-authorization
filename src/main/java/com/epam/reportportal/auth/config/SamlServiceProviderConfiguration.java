/*
 * Copyright 2019 EPAM Systems
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.epam.reportportal.auth.config;

import com.epam.reportportal.auth.integration.converter.SamlDetailsConverter;
import com.epam.reportportal.auth.util.CertificationUtil;
import com.epam.ta.reportportal.dao.SamlProviderDetailsRepository;
import com.epam.ta.reportportal.entity.saml.SamlProviderDetails;
import org.opensaml.saml.saml2.core.NameID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.config.NetworkConfiguration;
import org.springframework.security.saml.provider.config.RotatingKeys;
import org.springframework.security.saml.provider.service.config.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.service.config.LocalServiceProviderConfiguration;
import org.springframework.util.CollectionUtils;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static java.util.Base64.getEncoder;

/**
 * SAML service provider configuration based on application settings
 *
 * @author Yevgeniy Svalukhin
 */
@Configuration
public class SamlServiceProviderConfiguration {

	@Value("${rp.auth.saml.base-path}")
	private String basePath;

	@Value("${rp.auth.saml.key-alias}")
	private String keyAlias;

	@Value("${rp.auth.saml.key-password}")
	private String keyPassword;

	@Value("${rp.auth.saml.key-store}")
	private String keyStore;

	@Value("${rp.auth.saml.key-store-password}")
	private String keyStorePassword;

	@Value("${rp.auth.saml.active-key-name}")
	private String activeKeyName;

	@Value("${rp.auth.saml.network-connection-timeout}")
	private Integer networkConnectTimeout;

	@Value("${rp.auth.saml.network-read-timeout}")
	private Integer networkReadTimeout;

	@Value("${rp.auth.saml.signed-requests}")
	private Boolean signedRequests;

	private SamlProviderDetailsRepository samlProviderDetailsRepository;

	public SamlServiceProviderConfiguration(SamlProviderDetailsRepository samlProviderDetailsRepository) {
		this.samlProviderDetailsRepository = samlProviderDetailsRepository;
	}

	@Bean(name = "spConfiguration")
	public SamlServerConfiguration samlServerConfiguration() {
		return new SamlServerConfiguration().setServiceProvider(serviceProviderConfiguration()).setNetwork(networkConfiguration());
	}

	private NetworkConfiguration networkConfiguration() {
		return new NetworkConfiguration().setConnectTimeout(networkConnectTimeout).setReadTimeout(networkReadTimeout);

	}

	private LocalServiceProviderConfiguration serviceProviderConfiguration() {
		LocalServiceProviderConfiguration serviceProviderConfiguration = new LocalServiceProviderConfiguration();
		serviceProviderConfiguration.setSignRequests(signedRequests)
				.setWantAssertionsSigned(signedRequests)
				.setEntityId("report.portal.sp.id")
				.setAlias("report-portal-sp")
				.setSignMetadata(signedRequests)
				.setSingleLogoutEnabled(true)
				.setNameIds(Arrays.asList(NameID.EMAIL, NameID.PERSISTENT, NameID.UNSPECIFIED))
				.setKeys(rotatingKeys())
				.setProviders(providers())
				.setPrefix("saml/sp")
				.setBasePath(basePath);
		return serviceProviderConfiguration;
	}

	private List<ExternalIdentityProviderConfiguration> providers() {

		List<SamlProviderDetails> providers = samlProviderDetailsRepository.findAll();

		if (CollectionUtils.isEmpty(providers)) {
			return new CopyOnWriteArrayList<>();
		}

		return new CopyOnWriteArrayList<>(SamlDetailsConverter.TO_EXTERNAL_PROVIDER_CONFIG.apply(providers));
	}

	private RotatingKeys rotatingKeys() {
		return new RotatingKeys().setActive(activeKey()).setStandBy(standbyKeys());
	}

	private List<SimpleKey> standbyKeys() {
		return Collections.emptyList();
	}

	private SimpleKey activeKey() {

		if (signedRequests) {
			X509Certificate certificate = CertificationUtil.getCertificateByName(keyAlias, keyStore, keyStorePassword);
			PrivateKey privateKey = CertificationUtil.getPrivateKey(keyAlias, keyPassword, keyStore, keyStorePassword);

			try {
				return new SimpleKey().setCertificate(getEncoder().encodeToString(certificate.getEncoded()))
						.setPassphrase(keyPassword)
						.setPrivateKey(getEncoder().encodeToString(privateKey.getEncoded()))
						.setName(activeKeyName);
			} catch (CertificateEncodingException e) {
				e.printStackTrace();
			}
		}
		return new SimpleKey();
	}

}