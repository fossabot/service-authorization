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

package com.epam.reportportal.auth.integration.handler.impl;

import com.epam.reportportal.auth.integration.converter.LdapConverter;
import com.epam.reportportal.auth.integration.handler.GetAuthIntegrationStrategy;
import com.epam.ta.reportportal.dao.IntegrationRepository;
import com.epam.ta.reportportal.entity.ldap.LdapConfig;
import com.epam.ta.reportportal.ws.model.integration.auth.AbstractLdapResource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * @author <a href="mailto:ivan_budayeu@epam.com">Ivan Budayeu</a>
 */
@Service
public class GetLdapStrategy implements GetAuthIntegrationStrategy {

	private final IntegrationRepository integrationRepository;

	@Autowired
	public GetLdapStrategy(IntegrationRepository integrationRepository) {
		this.integrationRepository = integrationRepository;
	}

	@Override
	public AbstractLdapResource getIntegration() {

		//or else empty integration with default 'enabled = false' flag
		return LdapConverter.TO_RESOURCE.apply(integrationRepository.findLdap().orElseGet(LdapConfig::new));
	}
}
