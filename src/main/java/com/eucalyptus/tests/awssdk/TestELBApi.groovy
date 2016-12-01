package com.eucalyptus.tests.awssdk

import com.amazonaws.AmazonServiceException
import com.amazonaws.auth.AWSCredentialsProvider
import com.amazonaws.auth.BasicAWSCredentials
import com.amazonaws.internal.StaticCredentialsProvider
import com.amazonaws.services.elasticloadbalancing.AmazonElasticLoadBalancing
import com.amazonaws.services.elasticloadbalancing.AmazonElasticLoadBalancingClient
import com.amazonaws.services.elasticloadbalancing.model.*
import org.testng.annotations.Test

import static N4j.*

/**
 * ELB API basic test.
 *
 * - tests delete success on invalid elb name
 * - tests describe of example policies
 */
class TestELBApi {
  private final String host;
  private final AWSCredentialsProvider credentials;

  public TestELBApi( ) {
    minimalInit()
    this.host = CLC_IP
    this.credentials = new StaticCredentialsProvider( new BasicAWSCredentials( ACCESS_KEY, SECRET_KEY ) )
  }

  private String cloudUri( String servicePath ) {
    URI.create( "http://" + host + ":8773/" )
        .resolve( servicePath )
        .toString()
  }

  private AmazonElasticLoadBalancing getELBClient( final AWSCredentialsProvider credentials ) {
    final AmazonElasticLoadBalancing elb = new AmazonElasticLoadBalancingClient( credentials )
    elb.setEndpoint( cloudUri( "/services/LoadBalancing" ) )
    elb
  }

  @Test
  public void testElbApi( ) throws Exception {
    final AmazonElasticLoadBalancing elb = getELBClient( credentials )
    final String elbInvalidName = 'invalid name for a load balancer'
    final List<Runnable> cleanupTasks = [] as List<Runnable>
    try {
      elb.with {
        print( 'Describing load balancers' )
        print( describeLoadBalancers( ).toString( ) )

        print( 'Describing load balancer tags' )
        try {
          print( describeTags( new DescribeTagsRequest( loadBalancerNames: [ elbInvalidName ] ) ).toString( ) )
        } catch ( AmazonServiceException e ) {
          print( "Got error for request with invalid name: ${e}" )
        }

        print( 'Describing load balancer attributes' )
        try {
          describeLoadBalancerAttributes( new DescribeLoadBalancerAttributesRequest(
              loadBalancerName: elbInvalidName
          ) )
        } catch ( AmazonServiceException e ) {
          print( "Got error for request with invalid name: ${e}" )
        }

        print( 'Deleting invalid load balancer' )
        deleteLoadBalancer( new DeleteLoadBalancerRequest(
            loadBalancerName: elbInvalidName
        ))

        print( 'Describing policy types' )
        describeLoadBalancerPolicyTypes( ).with {
          print( it.toString( ) )
          assertThat( policyTypeDescriptions != null, 'Expected policy type descriptions' )
          assertThat( !policyTypeDescriptions.isEmpty( ), "Expected policy type descriptions but was empty" )
          policyTypeDescriptions.each {
            assertThat( it.policyTypeName != null, 'Expected policy type name' )
            assertThat( it.description != null, 'Expected description' )
          }
        }

        print( 'Describing load balancer policies' )
        describeLoadBalancerPolicies( new DescribeLoadBalancerPoliciesRequest( ) ).with {
          print( it.toString( ) )
          assertThat( policyDescriptions != null, 'Expected policy descriptions' )
          assertThat( !policyDescriptions.isEmpty( ), "Expected policy descriptions but was empty" )
          policyDescriptions.each {
            assertThat( it.policyName != null, 'Expected policy name' )
            assertThat( it.policyName.startsWith( 'ELBSample-' ) || it.policyName.startsWith( 'ELBSecurityPolicy-' ),
                "Expected sample policy name to start with 'ELBSample-' or 'ELBSecurityPolicy-', but was ${it.policyName}" )
          }
        }

        void
      }

      print( "Test complete" )
    } finally {
      // Attempt to clean up anything we created
      cleanupTasks.reverseEach { Runnable cleanupTask ->
        try {
          cleanupTask.run()
        } catch ( Exception e ) {
          e.printStackTrace()
        }
      }
    }
  }
}
