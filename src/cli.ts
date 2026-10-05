#!/usr/bin/env node

import {
  booleanArgument,
  enumArgument,
  mapArgument,
  parseCliArguments,
  stringArgument,
  stringArrayArgument
} from '@actsecurity/cli'
import { NoCacheProvider } from './collect/client.js'
import { getCollectClient, loadCollectConfigs } from './collect/collect.js'
import { principalCan } from './principalCan/principalCan.js'
import { makePrincipalIndex } from './principalIndex/makePrincipalIndex.js'
import { selectSimulateCliVariant } from './simulate/cliVariant.js'
import {
  resultMatchesExpectation,
  simulateAnonymousRequest,
  simulateExternalPrincipalRequest,
  simulateExternalResourceRequest,
  simulateRequest
} from './simulate/simulate.js'
import { iamLensVersion } from './utils/packageVersion.js'
import { stringOrFileArgument } from './utils/stringOrFileArgument.js'
import { whoCan } from './whoCan/whoCan.js'

const main = async () => {
  const cli = await parseCliArguments(
    'iam-lens',
    {
      simulate: {
        description: 'Simulate an IAM request',
        arguments: {
          principal: stringArgument({
            description: 'The principal to simulate. Can be a user, role, session, or AWS service'
          }),
          resource: stringArgument({
            description:
              'The ARN of the resource to simulate access to. Ignore for wildcard actions'
          }),
          resourceAccount: stringArgument({
            description:
              'The account ID of the resource, only required if it cannot be determined from the resource ARN.'
          }),
          action: stringArgument({
            description:
              'The action to simulate; must be a valid IAM service and action such as `s3:ListBucket`'
          }),
          context: mapArgument({
            description:
              'The context keys to use for the simulation. The first value is the key and the rest are the values. Specify multiple keys by using --context multiple times',
            defaultValue: {}
          }),
          verbose: booleanArgument({
            description: 'Enable verbose output for the simulation',
            character: 'v'
          }),
          expect: enumArgument({
            description:
              'The expected result of the simulation, if the result does not match the expected response a non-zero exit code will be returned',
            validValues: ['Allowed', 'ImplicitlyDenied', 'ExplicitlyDenied', 'AnyDeny']
          }),
          anonymous: booleanArgument({
            description:
              'Simulate an unsigned request to a concrete resource ARN. Wildcard-only actions are unsupported; cannot be combined with --principal or --session-policy',
            character: 'a'
          }),
          externalPrincipal: booleanArgument({
            description:
              'Simulate an uncollected principal with an allow-all identity policy and no SCPs. Wildcard-only actions are unsupported',
            character: 'e'
          }),
          externalResource: booleanArgument({
            description:
              'Simulate a concrete resource ARN outside the dataset with no RCPs and an allow-all resource or trust policy. Wildcard-only actions are unsupported',
            character: 'x'
          }),
          resourcePolicy: stringOrFileArgument({
            description:
              'Resource policy for --external-resource, or trust policy for an STS assume-role action'
          }),
          s3AbacOverride: enumArgument({
            description:
              'Override the S3 ABAC setting for S3 buckets. Defaults to the bucket setting stored in your iam-collect data',
            validValues: ['enabled', 'disabled'],
            defaultValue: undefined
          }),
          sessionPolicy: stringOrFileArgument({
            description:
              'The session policy to use for the simulation, if the principal type supports it'
          })
        }
      },
      'who-can': {
        description: 'Find who can perform an action on a resource',
        arguments: {
          resource: stringArgument({
            description:
              'The ARN of the resource to check permissions for. Ignore for wildcard actions'
          }),
          resourceAccount: stringArgument({
            description:
              'The account ID of the resource, only required if it cannot be determined from the resource ARN. Required for wildcard actions'
          }),
          actions: stringArrayArgument({
            description:
              'The actions to check permissions for; must be a valid IAM service and action such as `s3:GetObject`',
            defaultValue: []
          }),
          s3AbacOverride: enumArgument({
            description:
              'Override the S3 ABAC setting for S3 buckets. Defaults to the bucket setting stored in your iam-collect data',
            validValues: ['enabled', 'disabled'],
            defaultValue: undefined
          }),
          sort: booleanArgument({
            description: 'Sort the results before outputting',
            character: 's'
          })
        }
      },
      'principal-can': {
        description:
          'Create a consolidated view of all permissions for a principal, see readme for limitations',
        arguments: {
          principal: stringArgument({
            description: 'The principal to check permissions for. Can be a user or role'
          }),
          shrinkActionLists: booleanArgument({
            description: 'Shrink action lists to reduce policy size',
            character: 's'
          })
        }
      },
      'index-principals': {
        description: 'Index all principals',
        arguments: {}
      }
    },
    {
      collectConfigs: stringArrayArgument({
        description: 'The iam-collect configuration files to use',
        defaultValue: []
      }),
      partition: stringArgument({
        description: 'The AWS partition to use (aws, aws-cn, aws-us-gov). Defaults to aws',
        defaultValue: 'aws'
      })
    },
    {
      envPrefix: 'IAM_LENS',
      showHelpIfNoArgs: true,
      requireSubcommand: true,
      expectOperands: false,
      version: {
        currentVersion: iamLensVersion,
        checkForUpdates: '@actsecurity/iam-lens'
      }
    }
  )

  const simulateSelection =
    cli.subcommand === 'simulate'
      ? selectSimulateCliVariant({
          anonymous: cli.args.anonymous,
          externalPrincipal: cli.args.externalPrincipal,
          externalResource: cli.args.externalResource,
          principal: cli.args.principal,
          resource: cli.args.resource,
          resourceAccount: cli.args.resourceAccount,
          action: cli.args.action,
          customContextKeys: singularizeOneEntryArrays(cli.args.context),
          sessionPolicy: cli.args.sessionPolicy,
          resourcePolicy: cli.args.resourcePolicy,
          s3AbacOverride: cli.args.s3AbacOverride
        })
      : undefined

  if (cli.args.collectConfigs.length === 0) {
    cli.args.collectConfigs.push('./iam-collect.jsonc')
  }
  const collectConfigs = await loadCollectConfigs(cli.args.collectConfigs)
  const collectClient = await getCollectClient(collectConfigs, cli.args.partition)

  if (cli.subcommand === 'simulate') {
    const selection = simulateSelection!
    const { request, result } =
      selection.variant === 'anonymous'
        ? await simulateAnonymousRequest(selection.request, collectClient)
        : selection.variant === 'externalPrincipal'
          ? await simulateExternalPrincipalRequest(selection.request, collectClient)
          : selection.variant === 'externalResource'
            ? await simulateExternalResourceRequest(selection.request, collectClient)
            : await simulateRequest(selection.request, collectClient)

    if (result.resultType === 'error') {
      console.error('Simulation Errors:')
      console.log(JSON.stringify(result.errors, null, 2))
      process.exit(1)
    }

    console.log(`Simulation Result: ${result.overallResult}`)
    if (cli.args.verbose) {
      console.log(JSON.stringify({ request, result }, null, 2))
    }

    if (!resultMatchesExpectation(cli.args.expect, result.overallResult!)) {
      process.exit(1)
    }
  } else if (cli.subcommand === 'who-can') {
    const { resource, resourceAccount, actions } = cli.args
    if (!resourceAccount && !resource && actions.length === 0) {
      console.error(
        'Error: At least 1) resource or 2) resource-account and actions must be provided for who-can command'
      )
      process.exit(1)
    }

    const results = await whoCan(collectConfigs, cli.args.partition, {
      resource: cli.args.resource!,
      actions: cli.args.actions!,
      resourceAccount: cli.args.resourceAccount,
      s3AbacOverride: cli.args.s3AbacOverride,
      sort: cli.args.sort
    })

    console.log(JSON.stringify(results, null, 2))
  } else if (cli.subcommand === 'principal-can') {
    const { principal, shrinkActionLists } = cli.args
    if (!principal) {
      console.error('Error: Principal must be provided for principal-can command')
      process.exit(1)
    }

    const results = await principalCan(collectClient, {
      principal: principal,
      shrinkActionLists
    })

    console.log(JSON.stringify(results, null, 2))
  } else if (cli.subcommand === 'index-principals') {
    const indexClient = await getCollectClient(collectConfigs, cli.args.partition, {
      cacheProvider: new NoCacheProvider()
    })
    await makePrincipalIndex(indexClient)
  }
}

/**
 * Take a record of string arrays and convert it to a record of strings or string arrays,
 * where any array with a single element is converted to a string.
 *
 * @param input - The input record of string arrays.
 * @returns A new record with singularized values.
 */
function singularizeOneEntryArrays(
  input: Record<string, string[]>
): Record<string, string | string[]> {
  const output: Record<string, string | string[]> = {}
  for (const [key, value] of Object.entries(input)) {
    if (value.length === 1) {
      output[key] = value[0]
    } else {
      output[key] = value
    }
  }
  return output
}

main()
  .catch((e) => {
    console.error(e)
    process.exit(1)
  })
  .then(() => {})
  .finally(() => {})
