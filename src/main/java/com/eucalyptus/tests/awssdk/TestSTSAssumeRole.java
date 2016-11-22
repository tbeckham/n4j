/*************************************************************************
 * Copyright 2009-2016 Eucalyptus Systems, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/.
 *
 * Please contact Eucalyptus Systems, Inc., 6755 Hollister Ave., Goleta
 * CA 93117, USA or visit http://www.eucalyptus.com/licenses/ if you need
 * additional information or have any questions.
 ************************************************************************/
package com.eucalyptus.tests.awssdk;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.internal.StaticCredentialsProvider;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2Client;
import com.amazonaws.services.ec2.model.DescribeImagesRequest;
import com.amazonaws.services.ec2.model.DescribeImagesResult;
import com.amazonaws.services.ec2.model.Filter;
import com.amazonaws.services.identitymanagement.model.*;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClient;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityRequest;
import com.amazonaws.services.securitytoken.model.GetCallerIdentityResult;
import com.github.sjones4.youcan.youare.YouAreClient;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static com.eucalyptus.tests.awssdk.N4j.*;

/**
 * This test covers:
 *
 * <ul>
 *   <li>assuming an IAM role using STS</li>
 *   <li>consuming EC2 using the role</li>
 *   <li>getting caller identity from STS for users and roles</li>
 * </ul>
 *
 * <p/>
 * This is verification for the stories:
 * <p/>
 * <ul>
 * <li>https://eucalyptus.atlassian.net/browse/EUCA-5250</li>
 * <li>https://eucalyptus.atlassian.net/browse/EUCA-12318</li>
 * </ul>
 */
public class TestSTSAssumeRole {

    @Test
    public void STSAssumeRoleTest() throws Exception {
        testInfo(this.getClass().getSimpleName());
        getCloudInfo();
        final String user = NAME_PREFIX + "user";
        final String account = NAME_PREFIX + "account";

        final List<Runnable> cleanupTasks = new ArrayList<>();
        try {
            // Create role to get a client id
            final String accountId;

            // create non-admin user in non-euca account then get credentials and connection for user
            createAccount(account);
            createUser(account, user);
            createIAMPolicy( account, user, NAME_PREFIX + "policy",
                "{\"Statement\":[{\"Effect\":\"Allow\",\"Resource\":\"*\",\"Action\":[\"iam:*\"]}]}" );

            // get youAre connection for new user
            AWSCredentialsProvider awsCredentialsProvider = new StaticCredentialsProvider(getUserCreds(account,user));
            final YouAreClient youAre = new YouAreClient(awsCredentialsProvider);
            youAre.setEndpoint(IAM_ENDPOINT);

            cleanupTasks.add( () -> {
                print("Deleting account " + account);
                deleteAccount(account);
            } );

            final GetUserResult userResult = youAre.getUser(new GetUserRequest());
            assertThat(userResult.getUser() != null, "Expected current user info");
            assertThat(userResult.getUser().getArn() != null, "Expected current user ARN");
            final String userArn = userResult.getUser().getArn();
            final String userId = userResult.getUser().getUserId();
            print("Got user ARN (will convert account alias to ID if necessary): " + userArn);
            print("Got user id: " + userId);
            {
                final String roleNameA = NAME_PREFIX + "AssumeRoleTestA";
                print("Creating role to determine account number: " + roleNameA);
                final CreateRoleResult roleResult = youAre.createRole(new CreateRoleRequest()
                        .withRoleName(roleNameA)
                        .withAssumeRolePolicyDocument(
                                "{\n" +
                                        "    \"Statement\": [ {\n" +
                                        "      \"Effect\": \"Allow\",\n" +
                                        "      \"Principal\": {\n" +
                                        "         \"AWS\": [ \"" + userArn + "\" ]\n" +
                                        "      },\n" +
                                        "      \"Action\": [ \"sts:AssumeRole\" ],\n" +
                                        "      \"Condition\": {" +
                                        "         \"StringEquals\": {" +
                                        "           \"sts:ExternalId\": \"222222222222\"" +
                                        "         }" +
                                        "      }" +
                                        "    } ]\n" +
                                        "}"));
                cleanupTasks.add( () -> {
                    print("Deleting role: " + roleNameA);
                    youAre.deleteRole(new DeleteRoleRequest()
                            .withRoleName(roleNameA));
                } );
                assertThat(roleResult.getRole() != null, "Expected role");
                assertThat(roleResult.getRole().getArn() != null, "Expected role ARN");
                assertThat(roleResult.getRole().getArn().length() > 25, "Expected role ARN length to exceed 25 characters");
                final String roleArn = roleResult.getRole().getArn();
                accountId = roleArn.substring(13, 25);
            }
            final String userCleanedArn = "arn:aws:iam::" + accountId + ":" + userArn.substring(userArn.lastIndexOf(':') + 1);
            print("Using account id: " + accountId);
            print("Using user ARN in assume role policy: " + userCleanedArn);

            // Create role
            final String roleName = NAME_PREFIX + "AssumeRoleTest";
            print("Creating role: " + roleName);
            youAre.createRole(new CreateRoleRequest()
                    .withRoleName(roleName)
                    .withPath("/path")
                    .withAssumeRolePolicyDocument(
                            "{\n" +
                                    "    \"Statement\": [ {\n" +
                                    "      \"Effect\": \"Allow\",\n" +
                                    "      \"Principal\": {\n" +
                                    "         \"AWS\": [ \"" + userCleanedArn + "\" ]\n" +
                                    "      },\n" +
                                    "      \"Action\": [ \"sts:AssumeRole\" ],\n" +
                                    "      \"Condition\": {" +
                                    "         \"StringEquals\": {" +
                                    "           \"sts:ExternalId\": \"222222222222\"" +
                                    "         }" +
                                    "      }" +
                                    "    } ]\n" +
                                    "}"));
            cleanupTasks.add( () -> {
                print("Deleting role: " + roleName);
                youAre.deleteRole(new DeleteRoleRequest()
                        .withRoleName(roleName));
            } );

            // Get role info
            print("Getting role: " + roleName);
            final GetRoleResult result = youAre.getRole(new GetRoleRequest().withRoleName(roleName));
            assertThat(result.getRole() != null, "Expected role");
            assertThat(result.getRole().getArn() != null, "Expected role ARN");
            final String roleArn = result.getRole().getArn();
            final String roleId = result.getRole().getRoleId();
            print("Got role arn : " + roleArn);
            print("Got role id  : " + roleId);

            /* Describe images using role with no permissions
             * In 3.X this would just return nothing
             * In 4.0 should get error. see EUCA-8513
             */
            print("Describing images to ensure no permission with role: " + roleName);
            {
                try {
                    final DescribeImagesResult imagesResult = getImagesUsingRole(account, user, roleName, roleArn, "222222222222");
                    imagesResult.getImages();
                } catch (AmazonServiceException e) {
                    print("Got Expected Failure: " + e.getMessage());
                    assertThat(e.getMessage().length() > 0, "Should have failed to list images for role without expressed permission");
                }
            }

            // Add policy to role
            final String policyName = NAME_PREFIX + "AssumeRoleTestPolicy";
            print("Adding policy: " + policyName + " to role: " + roleName);
            youAre.putRolePolicy(new PutRolePolicyRequest()
                    .withRoleName(roleName)
                    .withPolicyName(policyName)
                    .withPolicyDocument(
                            "{\n" +
                                    "   \"Statement\":[{\n" +
                                    "      \"Effect\":\"Allow\",\n" +
                                    "      \"Action\":\"ec2:*\",\n" +
                                    "      \"Resource\":\"*\"\n" +
                                    "   }]\n" +
                                    "}"));
            cleanupTasks.add( () -> {
                print("Removing policy: " + policyName + ", from role: " + roleName);
                youAre.deleteRolePolicy(new DeleteRolePolicyRequest().withRoleName(roleName).withPolicyName(policyName));
            } );

            // Describe images using role
            try {
                final DescribeImagesResult imagesResult = getImagesUsingRole(account, user, roleName, roleArn, "222222222222");
                assertThat(imagesResult.getImages().size() > 0, "Image not found when using role");
                final String imageId = imagesResult.getImages().get(0).getImageId();
                print("Found image: " + imageId);
            } catch ( AmazonServiceException e ) {
                // TODO this catch block can be removed once this test no longer needs to pass against versions < 5.0
                print( "WARNING" );
                print( "WARNING: Unexpected exception assuming role with valid external id, assuming pre-5.0 behaviour: " + e);
                print( "WARNING" );
                print( "Authorizing actions on all services for user " + user );
                createIAMPolicy( account, user, NAME_PREFIX + "policy", null );
                print( "Sleeping to allow policy change to propagate" );
                N4j.sleep( 5 );
                {
                    final DescribeImagesResult imagesResult = getImagesUsingRole(account, user, roleName, roleArn, "222222222222");
                    assertThat(imagesResult.getImages().size() > 0, "Image not found when using role");
                    final String imageId = imagesResult.getImages().get(0).getImageId();
                    print("Found image: " + imageId);
                }
            }

            // Describe images using role with incorrect external id
            print("Ensuring listing images fails when incorrect external id used with role: " + roleName);
            try {
                getImagesUsingRole(account, user, roleName, roleArn, "222222222221");
                assertThat(false, "Expected error due to incorrect external id when assuming role (test must not be run as cloud admin)");
            } catch (AmazonServiceException e) {
                print("Received expected exception: " + e);
            }

            // Get caller identity using user credentials
            {
                print("Testing get caller identity for user credentials");
                final AWSSecurityTokenService sts = new AWSSecurityTokenServiceClient( awsCredentialsProvider );
                sts.setEndpoint(TOKENS_ENDPOINT);
                final GetCallerIdentityResult identityResult = sts.getCallerIdentity( new GetCallerIdentityRequest( ) );
                assertThat( accountId.equals( identityResult.getAccount( ) ), "Unexpected account for user caller identity : " + identityResult.getAccount( ) );
                assertThat( userArn.equals( identityResult.getArn( ) ), "Unexpected arn for user caller identity : " + identityResult.getArn( ) );
                assertThat( userId.equals( identityResult.getUserId( ) ), "Unexpected userid for user caller identity : " + identityResult.getUserId( ) );
            }


            // Get caller identity using role credentials
            {
                print("Testing get caller identity for role credentials");
                final String roleSessionName = "this-is-the-session-name";
                final String assumedRoleArn = "arn:aws:sts::"+accountId+":assumed-role/path/" + roleName + "/" + roleSessionName;
                final String assumedRoleId = roleId + ":" + roleSessionName;
                print("Expected assumed role arn : " + assumedRoleArn );
                print("Expected assumed role id  : " + assumedRoleId );
                final AWSSecurityTokenService sts = new AWSSecurityTokenServiceClient(
                    getCredentialsProviderForRole( awsCredentialsProvider, roleArn, "222222222222", roleSessionName ) );
                sts.setEndpoint(TOKENS_ENDPOINT);
                final GetCallerIdentityResult identityResult = sts.getCallerIdentity( new GetCallerIdentityRequest( ) );
                assertThat( accountId.equals( identityResult.getAccount( ) ), "Unexpected account for role caller identity : " + identityResult.getAccount( ) );
                assertThat( assumedRoleArn.equals( identityResult.getArn( ) ), "Unexpected arn for role caller identity : " + identityResult.getArn( ) );
                assertThat( assumedRoleId.equals( identityResult.getUserId( ) ), "Unexpected userid for role caller identity : " + identityResult.getUserId( ) );
            }

            print("Test complete");
        } finally {
            // Attempt to clean up anything we created
            Collections.reverse(cleanupTasks);
            for (final Runnable cleanupTask : cleanupTasks) {
                try {
                    cleanupTask.run();
                } catch (NoSuchEntityException e) {
                    print("Entity not found during cleanup.");
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private AWSCredentialsProvider getCredentialsProviderForRole( final AWSCredentials creds,
                                                                  final String roleArn,
                                                                  final String externalId,
                                                                  final String sessionName ) {
        return getCredentialsProviderForRole( new StaticCredentialsProvider( creds ), roleArn, externalId, sessionName );
    }

    private AWSCredentialsProvider getCredentialsProviderForRole( final AWSCredentialsProvider creds,
                                                                  final String roleArn,
                                                                  final String externalId,
                                                                  final String sessionName ) {
        return new AWSCredentialsProvider() {
            private AWSCredentials awsCredentials = null;

            @Override
            public AWSCredentials getCredentials() {
                if ( awsCredentials == null ) {
                    final AWSSecurityTokenService sts = new AWSSecurityTokenServiceClient(creds);
                    sts.setEndpoint(TOKENS_ENDPOINT);
                    final AssumeRoleResult assumeRoleResult = sts.assumeRole(new AssumeRoleRequest()
                        .withRoleArn(roleArn)
                        .withExternalId(externalId)
                        .withRoleSessionName(sessionName)
                    );

                    assertThat(assumeRoleResult.getAssumedRoleUser().getAssumedRoleId().endsWith(sessionName), "Unexpected assumed role id: " + assumeRoleResult.getAssumedRoleUser().getAssumedRoleId());
                    assertThat(assumeRoleResult.getAssumedRoleUser().getArn().endsWith(sessionName), "Unexpected assumed role arn: " + assumeRoleResult.getAssumedRoleUser().getArn());

                    awsCredentials = new BasicSessionCredentials(
                        assumeRoleResult.getCredentials().getAccessKeyId(),
                        assumeRoleResult.getCredentials().getSecretAccessKey(),
                        assumeRoleResult.getCredentials().getSessionToken()
                    );
                }
                return awsCredentials;
            }

            @Override
            public void refresh( ) {
                awsCredentials = null;
            }
        };
    }

    private AmazonEC2 getEc2ClientUsingRole(final String account,
                                            final String user,
                                            final String roleArn,
                                            final String externalId,
                                            final String sessionName) {
        final AmazonEC2 ec2 = new AmazonEC2Client( getCredentialsProviderForRole( getUserCreds(account,user), roleArn, externalId, sessionName ) );
        ec2.setEndpoint(EC2_ENDPOINT);
        return ec2;
    }

    private DescribeImagesResult getImagesUsingRole(final String account,
                                                    final String user,
                                                    final String roleName,
                                                    final String roleArn,
                                                    String externalId) {
        final AmazonEC2 ec2 = getEc2ClientUsingRole(account, user, roleArn, externalId, "session-name-here");

        print("Searching images using role: " + roleName);
        return ec2.describeImages(new DescribeImagesRequest().withFilters(
                new Filter().withName("image-type").withValues("machine"),
                new Filter().withName("root-device-type").withValues("instance-store")
        ));
    }
}
