package com.eucalyptus.tests.awssdk

import com.amazonaws.AmazonServiceException
import com.amazonaws.auth.*
import com.amazonaws.internal.StaticCredentialsProvider
import com.amazonaws.services.ec2.AmazonEC2
import com.amazonaws.services.ec2.AmazonEC2Client
import com.amazonaws.services.ec2.model.CreateSecurityGroupRequest
import com.amazonaws.services.ec2.model.DeleteSecurityGroupRequest
import com.amazonaws.services.ec2.model.DescribeSecurityGroupsResult
import com.amazonaws.services.identitymanagement.AmazonIdentityManagement
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClient
import com.amazonaws.services.identitymanagement.model.*
import com.amazonaws.services.securitytoken.AWSSecurityTokenService
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClient
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest
import com.amazonaws.services.securitytoken.model.GetCallerIdentityRequest
import org.testng.annotations.AfterClass
import org.testng.annotations.Test

import static com.eucalyptus.tests.awssdk.N4j.CLC_IP
import static com.eucalyptus.tests.awssdk.N4j.NAME_PREFIX

/**
 * Test STS AssumeRole policies.
 *
 * Test assuming role as a user with only a resource policy (i.e. no user/group policy authorizing role use)
 *
 * This test covers the issues:
 *   https://eucalyptus.atlassian.net/browse/EUCA-12957
 */
class TestSTSAssumeRolePolicy {

  private final int sleepSecs = 1
  private final String host
  private final String testAcct
  private final AWSCredentialsProvider adminCredentials
  private final String otherTestAcct
  private final AWSCredentialsProvider otherAdminCredentials

  public TestSTSAssumeRolePolicy( ) {
    N4j.getCloudInfo( )
    this.host = CLC_IP
    this.testAcct= "${NAME_PREFIX}test-acct"
    N4j.createAccount(testAcct)
    this.adminCredentials = new StaticCredentialsProvider( N4j.getUserCreds(testAcct, 'admin') )

    this.otherTestAcct= "${NAME_PREFIX}other-test-acct"
    N4j.createAccount(otherTestAcct)
    this.otherAdminCredentials = new StaticCredentialsProvider( N4j.getUserCreds(otherTestAcct, 'admin') )
  }

  /**
   * Called after all the tests in a class
   *
   * @throws java.lang.Exception
   */
  @AfterClass
  public void tearDownAfterClass() throws Exception {
    N4j.deleteAccount(testAcct)
    N4j.deleteAccount(otherTestAcct)
  }

  private String cloudUri(String servicePath) {
    URI.create("http://${host}:8773/")
            .resolve(servicePath)
            .toString()
  }

  private AWSSecurityTokenService getStsClient(final AWSCredentialsProvider credentials) {
    final AWSSecurityTokenService sts = new AWSSecurityTokenServiceClient(credentials)
    sts.setEndpoint(cloudUri('/services/Tokens'))
    sts
  }

  private AmazonIdentityManagement getIamClient(final AWSCredentialsProvider credentials) {
    final AmazonIdentityManagement iam = new AmazonIdentityManagementClient(credentials)
    iam.setEndpoint(cloudUri('/services/Euare'))
    iam
  }

  private AmazonEC2 getEC2Client(final AWSCredentialsProvider credentials) {
    final AmazonEC2 ec2 = new AmazonEC2Client(credentials)
    ec2.setEndpoint(cloudUri("/services/compute"))
    ec2
  }

  @Test
  public void assumeRolePolicyTest( ) throws Exception {
    final String namePrefix = NAME_PREFIX
    N4j.print( "Using resource prefix for test: ${namePrefix}" )

    final List<Runnable> cleanupTasks = [] as List<Runnable>
    try {
      N4j.print( "Getting account id for other account: ${otherTestAcct}" )
      String otherAccountNumber = getStsClient( otherAdminCredentials ).with {
        getCallerIdentity( new GetCallerIdentityRequest( ) ).with {
          account
        }
      }
      N4j.print( "Other account id: ${otherAccountNumber}" )
      N4j.assertThat( otherAccountNumber != null, 'Expected other account number' )

      String userName = "${namePrefix}assume-role-user"
      AWSCredentialsProvider userCredentials = null
      String userArn = null
      String roleArn = null
      String untrustingRoleArn = null
      getIamClient(adminCredentials).with {
        N4j.print( "Creating user for assuming role: ${userName}" )
        userArn = createUser( new CreateUserRequest( userName: userName, path: '/' ) ).with {
          user?.arn
        }
        cleanupTasks.add{
          N4j.print( "Deleting user: ${userName}" )
          deleteUser( new DeleteUserRequest( userName: userName ) )
        }
        N4j.print( "Got user arn: ${userArn}" )
        N4j.assertThat( userArn != null, 'Expected user arn' )

        N4j.print("Creating credentials for user: ${userName}")
        userCredentials = createAccessKey( new CreateAccessKeyRequest( userName: userName ) ).with {
          new StaticCredentialsProvider( new BasicAWSCredentials(
              accessKey.accessKeyId,
              accessKey.secretAccessKey
          ) );
        }
        cleanupTasks.add{
          N4j.print("Deleting credentials for user: ${userName}")
          deleteAccessKey( new DeleteAccessKeyRequest(
              userName: userName,
              accessKeyId: userCredentials.credentials.AWSAccessKeyId
          ) )
        }

        final String untrustPolicy = """\
          {
            "Version": "2012-10-17",
            "Statement": [
              {
                "Effect": "Allow",
                "Principal": {
                  "AWS": "${userArn.replace(userName,'admin')}"
                },
                "Action": "sts:AssumeRole"
              }
            ]
          }
        """.stripIndent()

        final String trustPolicy = """\
          {
            "Version": "2012-10-17",
            "Statement": [
              {
                "Effect": "Allow",
                "Principal": {
                  "AWS": [
                    "${userArn}",
                    "${otherAccountNumber}"
                  ]
                },
                "Action": "sts:AssumeRole"
              }
            ]
          }
        """.stripIndent()

        final String permissionPolicy = """\
          {
            "Version": "2012-10-17",
            "Statement": [
              {
                "Effect": "Allow",
                "Action": "ec2:*SecurityGroup*",
                "Resource": "*"
              }
            ]
          }
        """.stripIndent()

        // ensure iam user available when creating role
        N4j.print "Sleeping ${sleepSecs} seconds to ensure iam user available for use"
        N4j.sleep sleepSecs



        String untrustingRoleName = "${namePrefix}untrusting-role"
        N4j.print "Creating role: ${untrustingRoleName}"
        untrustingRoleArn = createRole(new CreateRoleRequest(
            path: '/',
            roleName: untrustingRoleName,
            assumeRolePolicyDocument: untrustPolicy
        ))?.with {
          role?.arn
        }
        N4j.print "Created role: ${untrustingRoleArn}"
        cleanupTasks.add {
          N4j.print "Deleting role: ${untrustingRoleArn}"
          deleteRole(new DeleteRoleRequest(
              roleName: untrustingRoleName
          ))
        }

        String roleName = "${namePrefix}role"
        N4j.print "Creating role: ${roleName}"
        roleArn = createRole(new CreateRoleRequest(
                path: '/',
                roleName: roleName,
                assumeRolePolicyDocument: trustPolicy
        ))?.with {
          role?.arn
        }
        N4j.print "Created role: ${roleArn}"
        cleanupTasks.add {
          N4j.print "Deleting role: ${roleArn}"
          deleteRole(new DeleteRoleRequest(
                  roleName: roleName
          ))
        }

        N4j.print "Creating role permission policy: ${roleName}/role-policy"
        putRolePolicy(new PutRolePolicyRequest(
                roleName: roleName,
                policyName: 'role-policy',
                policyDocument: permissionPolicy
        ))
        N4j.print "Created iam resources for assuming role"
        cleanupTasks.add {
          N4j.print "Deleting role policy: ${roleName}/role-policy"
          deleteRolePolicy(new DeleteRolePolicyRequest(
                  roleName: roleName,
                  policyName: 'role-policy',
          ))
        }
      }

      // ensure iam resources available
      N4j.print "Sleeping ${sleepSecs} seconds to ensure iam resources are available for use"
      N4j.sleep sleepSecs

      String roleCredentialsProviderArn = ''
      AWSCredentialsProvider roleCredentialsProviderCredentials = null
      final AWSCredentialsProvider roleCredentialsProvider = new AWSCredentialsProvider() {
        AWSCredentials awsCredentials = null
        @Override
        public AWSCredentials getCredentials( ) {
          if ( awsCredentials == null ) {
            N4j.print "Getting credentials using assume role"
            awsCredentials = getStsClient( roleCredentialsProviderCredentials ).with {
              assumeRole( new AssumeRoleRequest(
                  roleArn: roleCredentialsProviderArn,
                  roleSessionName: 'session-name-here'
              ) ).with {
                N4j.assertThat(assumedRoleUser != null, "Expected assumedRoleUser")
                N4j.assertThat(assumedRoleUser.arn != null, "Expected assumedRoleUser.arn")
                N4j.assertThat(assumedRoleUser.assumedRoleId != null, "Expected assumedRoleUser.assumedRoleId")
                N4j.assertThat(packedPolicySize == null, "Unexpected packedPolicySize")
                N4j.assertThat(credentials != null, "Expected credentials")
                N4j.assertThat(credentials.expiration != null, "Expected credentials expiration")
                new BasicSessionCredentials(
                    credentials.accessKeyId,
                    credentials.secretAccessKey,
                    credentials.sessionToken
                )
              }
            }
          }
          awsCredentials
        }

        @Override
        public void refresh( ) {
          awsCredentials = null
        }
      }

      N4j.print 'Testing access for untrusted user in same account using role'
      roleCredentialsProviderArn = untrustingRoleArn
      roleCredentialsProviderCredentials = userCredentials
      roleCredentialsProvider.refresh( )
      try {
        getEC2Client( roleCredentialsProvider ).with {
          N4j.print "Describing security groups using assumed role credentials (should fail)"
          describeSecurityGroups( )
          N4j.assertThat( false, 'Expected failure due to user not permitted to assume role' )
        }
      } catch ( AmazonServiceException e ) {
        N4j.print "Expected exception for assuming role without being trusted: ${e}"
      }

      N4j.print 'Testing access for trusted user in same account using role'
      roleCredentialsProviderArn = roleArn
      roleCredentialsProviderCredentials = userCredentials
      roleCredentialsProvider.refresh( )
      getEC2Client( roleCredentialsProvider ).with {
        N4j.print "Describing security groups using assumed role credentials"
        N4j.print describeSecurityGroups( ).with { DescribeSecurityGroupsResult result ->
          N4j.assertThat( securityGroups!=null && securityGroups.size()>0, "Expected visible security groups" )
          result.toString( )
        }

        String groupName = "${namePrefix}group-1"
        N4j.print "Creating security group ${groupName} using assumed role credentials"
        createSecurityGroup( new CreateSecurityGroupRequest( groupName: groupName, description: 'STS assume role with web identity test group' ) )

        N4j.print "Deleting security group ${groupName} using assumed role credentials"
        deleteSecurityGroup( new DeleteSecurityGroupRequest( groupName: groupName ) )
      }

      N4j.print 'Testing access for untrusted admin user in other account using role\''
      roleCredentialsProviderArn = untrustingRoleArn
      roleCredentialsProviderCredentials = otherAdminCredentials
      roleCredentialsProvider.refresh( )
      try {
        getEC2Client( roleCredentialsProvider ).with {
          N4j.print "Describing security groups using assumed role credentials (should fail)"
          describeSecurityGroups( )
          N4j.assertThat( false, 'Expected failure due to user not permitted to assume role' )
        }
      } catch ( AmazonServiceException e ) {
        N4j.print "Expected exception for assuming role without being trusted: ${e}"
      }

      N4j.print 'Testing access for trusted admin user in other account using role'
      roleCredentialsProviderArn = roleArn
      roleCredentialsProviderCredentials = otherAdminCredentials
      roleCredentialsProvider.refresh( )
      getEC2Client( roleCredentialsProvider ).with {
        N4j.print "Describing security groups using assumed role credentials"
        N4j.print describeSecurityGroups().with { DescribeSecurityGroupsResult result ->
          N4j.assertThat(securityGroups != null && securityGroups.size() > 0, "Expected visible security groups")
          result.toString()
        }
      }

      AWSCredentialsProvider otherAccountUser1Credentials = null
      AWSCredentialsProvider otherAccountUser2Credentials = null
      getIamClient( otherAdminCredentials ).with {
        String userName1 = "${namePrefix}other-assume-role-user-1"
        String userName2 = "${namePrefix}other-assume-role-user-2"

        N4j.print("Creating user for assuming role: ${userName1}")
        createUser(new CreateUserRequest(userName: userName1, path: '/'))
        cleanupTasks.add {
          N4j.print("Deleting user: ${userName1}")
          deleteUser(new DeleteUserRequest(userName: userName1))
        }

        N4j.print("Creating credentials for user: ${userName1}")
        otherAccountUser1Credentials = createAccessKey(new CreateAccessKeyRequest(userName: userName1)).with {
          new StaticCredentialsProvider(new BasicAWSCredentials(
              accessKey.accessKeyId,
              accessKey.secretAccessKey
          ));
        }
        cleanupTasks.add {
          N4j.print("Deleting credentials for user: ${userName1}")
          deleteAccessKey(new DeleteAccessKeyRequest(
              userName: userName1,
              accessKeyId: otherAccountUser1Credentials.credentials.AWSAccessKeyId
          ))
        }

        N4j.print("Creating user for assuming role: ${userName2}")
        createUser(new CreateUserRequest(userName: userName2, path: '/'))
        cleanupTasks.add {
          N4j.print("Deleting user: ${userName2}")
          deleteUser(new DeleteUserRequest(userName: userName2))
        }

        N4j.print "Creating policy allowing role access for: ${userName2}/user-policy"
        putUserPolicy(new PutUserPolicyRequest(
            userName: userName2,
            policyName: 'user-policy',
            policyDocument: '''\
            {
              "Statement": {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": "*"
              }
            }
            '''.stripIndent( )
        ))
        cleanupTasks.add {
          N4j.print "Deleting user policy: ${userName2}/user-policy"
          deleteUserPolicy(new DeleteUserPolicyRequest(
              userName: userName2,
              policyName: 'user-policy',
          ))
        }

        N4j.print("Creating credentials for user: ${userName2}")
        otherAccountUser2Credentials = createAccessKey(new CreateAccessKeyRequest(userName: userName2)).with {
          new StaticCredentialsProvider(new BasicAWSCredentials(
              accessKey.accessKeyId,
              accessKey.secretAccessKey
          ));
        }
        cleanupTasks.add {
          N4j.print("Deleting credentials for user: ${userName2}")
          deleteAccessKey(new DeleteAccessKeyRequest(
              userName: userName2,
              accessKeyId: otherAccountUser2Credentials.credentials.AWSAccessKeyId
          ))
        }
      }

      N4j.print 'Testing access for untrusted user in other trusted account using role'
      roleCredentialsProviderArn = roleArn
      roleCredentialsProviderCredentials = otherAccountUser1Credentials
      roleCredentialsProvider.refresh( )
      try {
        getEC2Client( roleCredentialsProvider ).with {
          N4j.print "Describing security groups using assumed role credentials (should fail)"
          describeSecurityGroups( )
          N4j.assertThat( false, 'Expected failure due to user not permitted to assume role' )
        }
      } catch ( AmazonServiceException e ) {
        N4j.print "Expected exception for assuming role without being trusted: ${e}"
      }

      N4j.print 'Testing access for trusted user in other trusted account using role'
      roleCredentialsProviderArn = roleArn
      roleCredentialsProviderCredentials = otherAccountUser2Credentials
      roleCredentialsProvider.refresh( )
      getEC2Client( roleCredentialsProvider ).with {
        N4j.print "Describing security groups using assumed role credentials"
        N4j.print describeSecurityGroups().with { DescribeSecurityGroupsResult result ->
          N4j.assertThat(securityGroups != null && securityGroups.size() > 0, "Expected visible security groups")
          result.toString()
        }
      }

      N4j.print 'Test complete'
    } finally {
      // Attempt to clean up anything we created
      cleanupTasks.reverseEach { Runnable cleanupTask ->
        try {
          cleanupTask.run()
        } catch ( AmazonServiceException e ) {
          N4j.print "Error in clean up: ${e}"
        } catch ( Exception e ) {
          e.printStackTrace()
        }
      }
    }
  }
}
