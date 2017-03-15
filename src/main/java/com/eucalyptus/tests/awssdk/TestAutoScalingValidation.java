package com.eucalyptus.tests.awssdk;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.services.autoscaling.model.*;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static com.eucalyptus.tests.awssdk.N4j.*;

/**
 * This application tests parameter validation for auto scaling.
 * <p/>
 * This is verification for:
 * <p/>
 * https://eucalyptus.atlassian.net/browse/EUCA-5016
 * https://eucalyptus.atlassian.net/browse/EUCA-13035
 */
public class TestAutoScalingValidation {

    @Test
    public void AutoScalingValidationTest() throws Exception {
        testInfo(this.getClass().getSimpleName());
        getCloudInfo();

        final List<Runnable> cleanupTasks = new ArrayList<Runnable>();
        try {
            // Register cleanup for launch configs
            final String configName = NAME_PREFIX + "ValidationTest";
            cleanupTasks.add(new Runnable() {
                @Override
                public void run() {
                    print("Deleting launch configuration: " + configName);
                    deleteLaunchConfig(configName);
                }
            });

            // Create launch configuration with invalid name
            print("Creating launch configuration with invalid name: " + configName + ":");
            try {
                as.createLaunchConfiguration(new CreateLaunchConfigurationRequest()
                        .withLaunchConfigurationName(configName + ":")
                        .withImageId(IMAGE_ID)
                        .withInstanceType(INSTANCE_TYPE));
                assertThat(false, "Expected error when creating launch configuration with invalid name");
            } catch (AmazonServiceException e) {
                print("Got expected exception: " + e);
                assertThat( e.getErrorCode( ) != null, "Expected error code" );
                assertThat( e.getErrorMessage( ) != null, "Expected error message" );
            }

            // Create launch configuration with missing required parameter
            print("Creating launch configuration with missing parameter: " + configName);
            try {
                as.createLaunchConfiguration(new CreateLaunchConfigurationRequest()
                        .withLaunchConfigurationName(configName + ":")
                        .withInstanceType(INSTANCE_TYPE));
                assertThat(false, "Expected error when creating launch configuration with missing parameter");
            } catch (AmazonServiceException e) {
                print("Got expected exception: " + e);
                assertThat( e.getErrorCode( ) != null, "Expected error code" );
                assertThat( e.getErrorMessage( ) != null, "Expected error message" );
            }

            // Create launch configuration
            print("Creating launch configuration: " + configName);
            as.createLaunchConfiguration(new CreateLaunchConfigurationRequest()
                    .withLaunchConfigurationName(configName)
                    .withImageId(IMAGE_ID)
                    .withInstanceType(INSTANCE_TYPE));

            // Register cleanup for auto scaling groups
            final String groupName = NAME_PREFIX + "ValidationTest";
            cleanupTasks.add(new Runnable() {
                @Override
                public void run() {
                    print("Deleting group: " + groupName);
                    deleteAutoScalingGroup(groupName,true);
                }
            });

            // Create scaling group with invalid size
            print("Creating auto scaling group with invalid size: " + groupName);
            try {
                as.createAutoScalingGroup(new CreateAutoScalingGroupRequest()
                        .withAutoScalingGroupName(groupName)
                        .withLaunchConfigurationName(configName)
                        .withMinSize(-1)
                        .withMaxSize(1)
                        .withAvailabilityZones(AVAILABILITY_ZONE)
                );
                assertThat(false, "Expected error when creating scaling group with invalid size");
            } catch (AmazonServiceException e) {
                print("Got expected exception: " + e);
                assertThat( e.getErrorCode( ) != null, "Expected error code" );
                assertThat( e.getErrorMessage( ) != null, "Expected error message" );
            }

            // Create scaling group with invalid capacity
            print("Creating auto scaling group with invalid capacity: " + groupName);
            try {
                as.createAutoScalingGroup(new CreateAutoScalingGroupRequest()
                        .withAutoScalingGroupName(groupName)
                        .withLaunchConfigurationName(configName)
                        .withMinSize(1)
                        .withMaxSize(1)
                        .withDesiredCapacity(2)
                        .withAvailabilityZones(AVAILABILITY_ZONE)
                );
                assertThat(false, "Expected error when creating scaling group with invalid capacity");
            } catch (AmazonServiceException e) {
                print("Got expected exception: " + e);
                assertThat( e.getErrorCode( ) != null, "Expected error code" );
                assertThat( e.getErrorMessage( ) != null, "Expected error message" );
            }

            // Create scaling group with invalid tag
            print("Creating auto scaling group with invalid tag: " + groupName);
            char[] nameSuffixChars = new char[128];
            Arrays.fill(nameSuffixChars, '1');
            String nameSuffix = new String(nameSuffixChars);
            try {
                as.createAutoScalingGroup(new CreateAutoScalingGroupRequest()
                        .withAutoScalingGroupName(groupName)
                        .withLaunchConfigurationName(configName)
                        .withMinSize(0)
                        .withMaxSize(0)
                        .withAvailabilityZones(AVAILABILITY_ZONE)
                        .withTags(
                                new Tag().withKey("tag1" + nameSuffix).withValue("propagate").withPropagateAtLaunch(Boolean.TRUE)
                        )
                );
                assertThat(false, "Expected error when creating scaling group with invalid tag");
            } catch (AmazonServiceException e) {
                print("Got expected exception: " + e);
                assertThat( e.getErrorCode( ) != null, "Expected error code" );
                assertThat( e.getErrorMessage( ) != null, "Expected error message" );
            }

            // Create scaling group with missing required parameter
            print("Creating auto scaling group with missing required parameters");
            try {
                as.createAutoScalingGroup( new CreateAutoScalingGroupRequest( )
                    .withAvailabilityZones( AVAILABILITY_ZONE ) );
                assertThat(false, "Expected error when creating scaling group with missing required parameters");
            } catch (AmazonServiceException e) {
                print("Got expected exception: " + e);
                assertThat( e.getErrorCode( ) != null, "Expected error code" );
                assertThat( e.getErrorMessage( ) != null, "Expected error message" );
            }

            // Create scaling group
            print("Creating auto scaling group: " + groupName);
            as.createAutoScalingGroup(new CreateAutoScalingGroupRequest()
                    .withAutoScalingGroupName(groupName)
                    .withLaunchConfigurationName(configName)
                    .withMinSize(0)
                    .withMaxSize(0)
                    .withAvailabilityZones(AVAILABILITY_ZONE));

            // Create tag on invalid group
            print("Creating tag on invalid group: " + groupName + ".invalid");
            try {
                as.createOrUpdateTags(new CreateOrUpdateTagsRequest().withTags(
                        new Tag().withResourceType("auto-scaling-group").withResourceId(groupName + ".invalid").withKey("tag1").withValue("propagate").withPropagateAtLaunch(Boolean.TRUE)
                ));
                assertThat(false, "Expected error when creating tag on invalid group");
            } catch (AmazonServiceException e) {
                print("Got expected exception: " + e);
                assertThat( e.getErrorCode( ) != null, "Expected error code" );
                assertThat( e.getErrorMessage( ) != null, "Expected error message" );
            }

            // Register cleanup for launch configs
            final String policyName = NAME_PREFIX + "ValidationTest";
            cleanupTasks.add(new Runnable() {
                @Override
                public void run() {
                    print("Deleting scaling policy: " + policyName);
                    as.deletePolicy(new DeletePolicyRequest().withAutoScalingGroupName(groupName).withPolicyName(policyName));
                }
            });

            // Create invalid scaling policy
            try {
                as.putScalingPolicy(new PutScalingPolicyRequest()
                        .withAutoScalingGroupName(groupName)
                        .withPolicyName(policyName)
                        .withScalingAdjustment(1)
                        .withAdjustmentType("ExactCapacity")
                        .withMinAdjustmentStep(1)
                );
                assertThat(false, "Expected error when creating invalid scaling policy");
            } catch (AmazonServiceException e) {
                print("Got expected exception: " + e);
                assertThat( e.getErrorCode( ) != null, "Expected error code" );
                assertThat( e.getErrorMessage( ) != null, "Expected error message" );
            }

            // Create invalid scaling policy
            try {
                as.putScalingPolicy(new PutScalingPolicyRequest()
                        .withAutoScalingGroupName(groupName)
                        .withPolicyName(policyName)
                        .withScalingAdjustment(-1)
                        .withAdjustmentType("ExactCapacity")
                );
                assertThat(false, "Expected error when creating invalid scaling policy");
            } catch (AmazonServiceException e) {
                print("Got expected exception: " + e);
                assertThat( e.getErrorCode( ) != null, "Expected error code" );
                assertThat( e.getErrorMessage( ) != null, "Expected error message" );
            }

            // Update group / set desired capacity with missing parameters
            try {
                as.updateAutoScalingGroup( new UpdateAutoScalingGroupRequest( ) );
                assertThat(false, "Expected error when updating scaling group without required parameters");
            } catch (AmazonServiceException e) {
                print("Got expected exception: " + e);
                assertThat( e.getErrorCode( ) != null, "Expected error code" );
                assertThat( e.getErrorMessage( ) != null, "Expected error message" );
            }
            try {
                as.setDesiredCapacity( new SetDesiredCapacityRequest( ) );
                assertThat(false, "Expected error when setting desired capacity for scaling group without required parameters");
            } catch (AmazonServiceException e) {
                print("Got expected exception: " + e);
                assertThat( e.getErrorCode( ) != null, "Expected error code" );
                assertThat( e.getErrorMessage( ) != null, "Expected error message" );
            }

            // Enable/disable metrics collection with missing parameters
            try {
                as.enableMetricsCollection( new EnableMetricsCollectionRequest( )
                    .withMetrics( "GroupMinSize" )
                    .withGranularity( "1Minute" )
                );
                assertThat(false, "Expected error when enabling metrics collection without required parameters");
            } catch (AmazonServiceException e) {
                print("Got expected exception: " + e);
                assertThat( e.getErrorCode( ) != null, "Expected error code" );
                assertThat( e.getErrorMessage( ) != null, "Expected error message" );
            }
            try {
                as.disableMetricsCollection( new DisableMetricsCollectionRequest( )
                    .withMetrics( "GroupMinSize" ) );
                assertThat(false, "Expected error when disabling metrics collection without required parameters");
            } catch (AmazonServiceException e) {
                print("Got expected exception: " + e);
                assertThat( e.getErrorCode( ) != null, "Expected error code" );
                assertThat( e.getErrorMessage( ) != null, "Expected error message" );
            }

            // Suspend/resume scaling processes with missing parameters
            try {
                as.suspendProcesses( new SuspendProcessesRequest( ) );
                assertThat(false, "Expected error when suspending processes without required parameters");
            } catch (AmazonServiceException e) {
                print("Got expected exception: " + e);
                assertThat( e.getErrorCode( ) != null, "Expected error code" );
                assertThat( e.getErrorMessage( ) != null, "Expected error message" );
            }
            try {
                as.resumeProcesses( new ResumeProcessesRequest( ) );
                assertThat(false, "Expected error when resuming processes without required parameters");
            } catch (AmazonServiceException e) {
                print("Got expected exception: " + e);
                assertThat( e.getErrorCode( ) != null, "Expected error code" );
                assertThat( e.getErrorMessage( ) != null, "Expected error message" );
            }

            // Put / execute scaling policies with missing parameters
            try {
                as.putScalingPolicy( new PutScalingPolicyRequest( ) );
                assertThat(false, "Expected error when putting scaling policy without required parameters");
            } catch (AmazonServiceException e) {
                print("Got expected exception: " + e);
                assertThat( e.getErrorCode( ) != null, "Expected error code" );
                assertThat( e.getErrorMessage( ) != null, "Expected error message" );
            }
            try {
                as.executePolicy( new ExecutePolicyRequest( ) );
                assertThat(false, "Expected error when executing scaling policy without required parameters");
            } catch (AmazonServiceException e) {
                print("Got expected exception: " + e);
                assertThat( e.getErrorCode( ) != null, "Expected error code" );
                assertThat( e.getErrorMessage( ) != null, "Expected error message" );
            }

            // Set instance health/terminate instance with missing parameters
            try {
                as.setInstanceHealth( new SetInstanceHealthRequest( ) );
                assertThat(false, "Expected error when setting instance health without required parameters");
            } catch (AmazonServiceException e) {
                print("Got expected exception: " + e);
                assertThat( e.getErrorCode( ) != null, "Expected error code" );
                assertThat( e.getErrorMessage( ) != null, "Expected error message" );
            }
            try {
                as.terminateInstanceInAutoScalingGroup( new TerminateInstanceInAutoScalingGroupRequest( ) );
                assertThat(false, "Expected error when terminating scaling instance without required parameters");
            } catch (AmazonServiceException e) {
                print("Got expected exception: " + e);
                assertThat( e.getErrorCode( ) != null, "Expected error code" );
                assertThat( e.getErrorMessage( ) != null, "Expected error message" );
            }

            print("Test complete");
        } finally {
            // Attempt to clean up anything we created
            Collections.reverse(cleanupTasks);
            for (final Runnable cleanupTask : cleanupTasks) {
                try {
                    cleanupTask.run();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
