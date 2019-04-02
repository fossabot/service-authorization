/*
 * Copyright 2016 EPAM Systems
 *
 *
 * This file is part of EPAM Report Portal.
 * https://github.com/reportportal/service-authorization
 *
 * Report Portal is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Report Portal is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Report Portal.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.epam.reportportal.auth.integration.github;

import com.epam.reportportal.auth.util.AuthUtils;
import com.epam.ta.reportportal.dao.OAuthRegistrationRestrictionRepository;
import com.epam.ta.reportportal.entity.oauth.OAuthRegistrationRestriction;
import com.epam.ta.reportportal.entity.user.User;
import com.epam.ta.reportportal.exception.ReportPortalException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

import java.io.Serializable;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Token services for GitHub account info with internal ReportPortal's database
 *
 * @author <a href="mailto:andrei_varabyeu@epam.com">Andrei Varabyeu</a>
 */
public class GitHubTokenServices implements ResourceServerTokenServices {

	private final GitHubUserReplicator replicator;

	private final OAuth2ProtectedResourceDetails detalis;

	private final OAuthRegistrationRestrictionRepository oAuthRegistrationRestrictionRepository;

	@Autowired
	public GitHubTokenServices(GitHubUserReplicator replicator, OAuth2ProtectedResourceDetails detalis,
			OAuthRegistrationRestrictionRepository oAuthRegistrationRestrictionRepository) {
		this.replicator = replicator;
		this.detalis = detalis;
		this.oAuthRegistrationRestrictionRepository = oAuthRegistrationRestrictionRepository;
	}

	@Override
	public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException, InvalidTokenException {
		GitHubClient gitHubClient = GitHubClient.withAccessToken(accessToken);
		UserResource gitHubUser = gitHubClient.getUser();

		Map<String, Object> userAttributes = gitHubClient.getUserAttributes();
		Set<String> allowedOrganizations = oAuthRegistrationRestrictionRepository.findByRegistrationId(detalis.getClientId())
				.stream()
				.filter(restriction -> "organization".equalsIgnoreCase(restriction.getType()))
				.map(OAuthRegistrationRestriction::getValue)
				.collect(Collectors.toSet());
		if (!allowedOrganizations.isEmpty()) {
			boolean assignedToOrganization = gitHubClient.getUserOrganizations(gitHubUser.login)
					.stream()
					.map(org -> org.login)
					.anyMatch(allowedOrganizations::contains);
			if (!assignedToOrganization) {
				throw new ReportPortalException("User '" + gitHubUser.login + "' does not belong to allowed GitHUB organization");
			}
		}

		User user = replicator.replicateUser(gitHubUser, gitHubClient);

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user.getId(),
				"N/A",
				AuthUtils.AS_AUTHORITIES.apply(user.getRole())
		);

		Map<String, Serializable> extensionProperties = Collections.singletonMap("upstream_token", accessToken);
		OAuth2Request request = new OAuth2Request(null, detalis.getClientId(), null, true, null, null, null, null, extensionProperties);
		return new OAuth2Authentication(request, token);

	}

	@Override
	public OAuth2AccessToken readAccessToken(String accessToken) {
		throw new UnsupportedOperationException("Not supported: read access token");
	}

	public static class InsufficientOrganizationException extends AuthenticationException {

		public InsufficientOrganizationException(String msg) {
			super(msg);
		}
	}

}
