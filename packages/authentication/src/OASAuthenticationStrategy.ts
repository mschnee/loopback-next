// Copyright IBM Corp. 2017,2020. All Rights Reserved.
// Node module: @loopback/authentication
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

import {
  Application,
  CoreBindings,
  DecoratorFactory,
  inject,
  MetadataInspector,
} from '@loopback/core';
import {
  mergeOpenAPISpec,
  mergeSecuritySchemeToSpec,
  OpenApiSpec,
  PathObject,
} from '@loopback/openapi-v3';
import {
  OASEnhancer,
  RedirectRoute,
  Request,
  RestEndpoint,
  SecuritySchemeObject,
} from '@loopback/rest';
import {UserProfile} from '@loopback/security';
import {
  AUTHENTICATION_METADATA_CLASS_KEY,
  AUTHENTICATION_METADATA_METHOD_KEY,
} from './keys';
import {AuthenticationMetadata, AuthenticationStrategy} from './types';

export abstract class OASAuthenticationStrategy
  implements AuthenticationStrategy, OASEnhancer {
  constructor(
    @inject(CoreBindings.APPLICATION_INSTANCE) protected app: Application,
  ) {}
  abstract name: string;
  abstract authenticate(
    request: Request,
  ): Promise<UserProfile | RedirectRoute | undefined>;
  abstract scheme(): SecuritySchemeObject;

  modifySpec(spec: OpenApiSpec): OpenApiSpec {
    let modifiedSpec = mergeSecuritySchemeToSpec(
      spec,
      this.name,
      this.scheme(),
    );
    for (const b of this.app.find(`${CoreBindings.CONTROLLERS}.*`)) {
      const controllerName = b.key.replace(/^controllers\./, '');
      const ctor = b.valueConstructor;
      if (!ctor) {
        throw new Error(
          `The controller ${controllerName} was not bound via .toClass()`,
        );
      }

      const classAuthMetadata = MetadataInspector.getClassMetadata<
        AuthenticationMetadata[]
      >(AUTHENTICATION_METADATA_CLASS_KEY, ctor.prototype);

      let endpoints =
        MetadataInspector.getAllMethodMetadata<RestEndpoint>(
          'openapi-v3:methods',
          ctor.prototype,
        ) ?? {};

      endpoints = DecoratorFactory.cloneDeep(endpoints);
      for (const op in endpoints) {
        const endpoint = endpoints[op];
        const verb = endpoint.verb!;
        const path = endpoint.path!;
        const methodAuthMetadata = MetadataInspector.getMethodMetadata<
          AuthenticationMetadata[]
        >(AUTHENTICATION_METADATA_METHOD_KEY, ctor.prototype, op);

        if (
          methodAuthMetadata?.some(m => m.strategy === this.name) ||
          classAuthMetadata?.some(m => m.strategy === this.name)
        ) {
          const mergeSpec: PathObject = {
            paths: {
              [path]: {
                [verb]: {
                  security: [
                    {
                      [this.name]: [
                        // scopes go here
                      ],
                    },
                  ],
                },
              },
            },
          };
          modifiedSpec = mergeOpenAPISpec(modifiedSpec, mergeSpec);
        }
      }
    }
    return modifiedSpec;
  }
}
