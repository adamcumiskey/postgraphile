// tslint:disable no-empty

import { $$pgClient } from '../../postgres/inventory/pgClientFromContext'
import withPostGraphileContext from '../withPostGraphileContext'

const jwt = require('jsonwebtoken')

/**
 * Expects an Http error. Passes if there is an error of the correct form,
 * fails if there is not.
 */
function expectHttpError(promise, statusCode, message) {
  return promise.then(
    () => {
      throw new Error('Expected a Http error.')
    },
    error => {
      expect(error.statusCode).toBe(statusCode)
      expect(error.message).toBe(message)
    },
  )
}

test('will be a noop for no token, secret, or default role', async () => {
  const pgClient = { query: jest.fn(), release: jest.fn() }
  const pgPool = { connect: jest.fn(() => pgClient) }
  await withPostGraphileContext({ pgPool }, () => {})
  expect(pgClient.query.mock.calls).toEqual([['begin'], ['commit']])
})

test('will pass in a context object with the client', async () => {
  const pgClient = { query: jest.fn(), release: jest.fn() }
  const pgPool = { connect: jest.fn(() => pgClient) }
  await withPostGraphileContext({ pgPool }, client => {
    expect(client[$$pgClient]).toBe(pgClient)
  })
})

test('will record queries run inside the transaction', async () => {
  const query1 = Symbol()
  const query2 = Symbol()
  const pgClient = { query: jest.fn(), release: jest.fn() }
  const pgPool = { connect: jest.fn(() => pgClient) }
  await withPostGraphileContext({ pgPool }, client => {
    client[$$pgClient].query(query1)
    client[$$pgClient].query(query2)
  })
  expect(pgClient.query.mock.calls).toEqual([
    ['begin'],
    [query1],
    [query2],
    ['commit'],
  ])
})

test('will return the value from the callback', async () => {
  const value = Symbol()
  const pgClient = { query: jest.fn(), release: jest.fn() }
  const pgPool = { connect: jest.fn(() => pgClient) }
  expect(await withPostGraphileContext({ pgPool }, () => value)).toBe(value)
})

test('will return the asynchronous value from the callback', async () => {
  const value = Symbol()
  const pgClient = { query: jest.fn(), release: jest.fn() }
  const pgPool = { connect: jest.fn(() => pgClient) }
  expect(
    await withPostGraphileContext({ pgPool }, () => Promise.resolve(value)),
  ).toBe(value)
})

test('will throw an error if there was a `jwtToekn`, but no `jwtOptions`', async () => {
  const pgClient = { query: jest.fn(), release: jest.fn() }
  const pgPool = { connect: jest.fn(() => pgClient) }
  await expectHttpError(
    withPostGraphileContext({pgPool, jwtToken: 'asd'}, () => {}),
    403,
    'Must provide jwtOptions when using jwt authentication'
  )
  expect(pgClient.query.mock.calls).toEqual([['begin'], ['commit']])
})

test('will throw an error if there was a `jwtToken`, but no `jwtOptions.secret`', async () => {
  const pgClient = { query: jest.fn(), release: jest.fn() }
  const pgPool = { connect: jest.fn(() => pgClient) }
  await expectHttpError(
    withPostGraphileContext({ pgPool, jwtToken: 'asd', jwtOptions: {} }, () => {}),
    403,
    'Not allowed to provide a JWT token.',
  )
  expect(pgClient.query.mock.calls).toEqual([['begin'], ['commit']])
})

test('will throw an error for a malformed `jwtToken`', async () => {
  const pgClient = { query: jest.fn(), release: jest.fn() }
  const pgPool = { connect: jest.fn(() => pgClient) }
  await expectHttpError(
    withPostGraphileContext(
      { pgPool, jwtToken: 'asd', jwtOptions: { secret: 'secret' }},
      () => {},
    ),
    403,
    'jwt malformed',
  )
  expect(pgClient.query.mock.calls).toEqual([['begin'], ['commit']])
})

test('will throw an error if the JWT token was signed with the wrong signature', async () => {
  const pgClient = { query: jest.fn(), release: jest.fn() }
  const pgPool = { connect: jest.fn(() => pgClient) }
  await expectHttpError(
    withPostGraphileContext(
      {
        pgPool,
        jwtToken: jwt.sign({ a: 1, b: 2, c: 3 }, 'wrong secret', {
          noTimestamp: true,
        }),
        jwtOptions: {
          secret: 'secret'
        }
      },
      () => {},
    ),
    403,
    'invalid signature',
  )
  expect(pgClient.query.mock.calls).toEqual([['begin'], ['commit']])
})

test('will throw an error if the JWT token does not have an audience', async () => {
  const pgClient = { query: jest.fn(), release: jest.fn() }
  const pgPool = { connect: jest.fn(() => pgClient) }
  await expectHttpError(
    withPostGraphileContext(
      {
        pgPool,
        jwtToken: jwt.sign({ a: 1, b: 2, c: 3 }, 'secret', {
          noTimestamp: true,
        }),
        jwtOptions: {
          secret: 'secret'
        }
      },
      () => {},
    ),
    403,
    'jwt audience invalid. expected: postgraphile',
  )
  expect(pgClient.query.mock.calls).toEqual([['begin'], ['commit']])
})

test('will throw an error if the JWT token does not have an appropriate audience', async () => {
  const pgClient = { query: jest.fn(), release: jest.fn() }
  const pgPool = { connect: jest.fn(() => pgClient) }
  await expectHttpError(
    withPostGraphileContext(
      {
        pgPool,
        jwtToken: jwt.sign({ a: 1, b: 2, c: 3, aud: 'postgrest' }, 'secret', {
          noTimestamp: true,
        }),
        jwtOptions: {
          secret: 'secret'
        }
      },
      () => {},
    ),
    403,
    'jwt audience invalid. expected: postgraphile',
  )
  expect(pgClient.query.mock.calls).toEqual([['begin'], ['commit']])
})

test('will succeed with all the correct things', async () => {
  const pgClient = { query: jest.fn(), release: jest.fn() }
  const pgPool = { connect: jest.fn(() => pgClient) }
  await withPostGraphileContext(
    {
      pgPool,
      jwtToken: jwt.sign({ aud: 'postgraphile' }, 'secret', {
        noTimestamp: true,
      }),
      jwtOptions: {
        secret: 'secret'
      }
    },
    () => {},
  )
  expect(pgClient.query.mock.calls).toEqual([
    ['begin'],
    [
      {
        text: 'select set_config($1, $2, true)',
        values: ['jwt.claims.aud', 'postgraphile'],
      },
    ],
    ['commit'],
  ])
})

test('will add extra claims as available', async () => {
  const pgClient = { query: jest.fn(), release: jest.fn() }
  const pgPool = { connect: jest.fn(() => pgClient) }
  await withPostGraphileContext(
    {
      pgPool,
      jwtToken: jwt.sign({ aud: 'postgraphile', a: 1, b: 2, c: 3 }, 'secret', {
        noTimestamp: true,
      }),
      jwtOptions: {
        secret: 'secret'
      }
    },
    () => {},
  )
  expect(pgClient.query.mock.calls).toEqual([
    ['begin'],
    [
      {
        text:
          'select set_config($1, $2, true), set_config($3, $4, true), set_config($5, $6, true), set_config($7, $8, true)',
        values: [
          'jwt.claims.aud',
          'postgraphile',
          'jwt.claims.a',
          1,
          'jwt.claims.b',
          2,
          'jwt.claims.c',
          3,
        ],
      },
    ],
    ['commit'],
  ])
})

test('will add extra settings as available', async () => {
  const pgClient = { query: jest.fn(), release: jest.fn() }
  const pgPool = { connect: jest.fn(() => pgClient) }
  await withPostGraphileContext(
    {
      pgPool,
      jwtToken: jwt.sign({ aud: 'postgraphile' }, 'secret', {
        noTimestamp: true,
      }),
      jwtOptions: {
        secret: 'secret'
      },
      pgSettings: {
        'foo.bar': 'test1',
        'some.other.var': 'hello world',
      },
    },
    () => {},
  )
  expect(pgClient.query.mock.calls).toEqual([
    ['begin'],
    [
      {
        text:
          'select set_config($1, $2, true), set_config($3, $4, true), set_config($5, $6, true)',
        values: [
          'foo.bar',
          'test1',
          'some.other.var',
          'hello world',
          'jwt.claims.aud',
          'postgraphile',
        ],
      },
    ],
    ['commit'],
  ])
})

test('undefined and null extra settings are ignored while 0 is converted to a string', async () => {
  const pgClient = { query: jest.fn(), release: jest.fn() }
  const pgPool = { connect: jest.fn(() => pgClient) }
  await withPostGraphileContext(
    {
      pgPool,
      jwtToken: jwt.sign({ aud: 'postgraphile' }, 'secret', {
        noTimestamp: true,
      }),
      jwtOptions: {
        secret: 'secret'
      },
      pgSettings: {
        'foo.bar': 'test1',
        'some.other.var': null,
        'some.setting.not.defined': undefined,
        'some.setting.zero': 0,
        'number.setting': 42,
      },
    },
    () => {},
  )
  expect(pgClient.query.mock.calls).toEqual([
    ['begin'],
    [
      {
        text:
          'select set_config($1, $2, true), set_config($3, $4, true), set_config($5, $6, true), set_config($7, $8, true)',
        values: [
          'foo.bar',
          'test1',
          'some.setting.zero',
          '0',
          'number.setting',
          '42',
          'jwt.claims.aud',
          'postgraphile',
        ],
      },
    ],
    ['commit'],
  ])
})

test('extra pgSettings that are objects throw an error', async () => {
  const pgClient = { query: jest.fn(), release: jest.fn() }
  const pgPool = { connect: jest.fn(() => pgClient) }
  let message
  try {
    await withPostGraphileContext(
      {
        pgPool,
        jwtToken: jwt.sign({ aud: 'postgraphile' }, 'secret', {
          noTimestamp: true,
        }),
        jwtOptions: {
          secret: 'secret'
        },
        pgSettings: {
          'some.object': { toString: () => 'SomeObject' },
        },
      },
      () => {},
    )
  } catch (error) {
    message = error.message
  }
  expect(message).toBe(
    'Error converting pgSetting: object needs to be of type string or number.',
  )
})

test('extra pgSettings that are symbols throw an error', async () => {
  const pgClient = { query: jest.fn(), release: jest.fn() }
  const pgPool = { connect: jest.fn(() => pgClient) }
  let message
  try {
    await withPostGraphileContext(
      {
        pgPool,
        jwtToken: jwt.sign({ aud: 'postgraphile' }, 'secret', {
          noTimestamp: true,
        }),
        jwtOptions: {
          secret: 'secret'
        },
        pgSettings: {
          'some.symbol': Symbol('some.symbol'),
        },
      },
      () => {},
    )
  } catch (error) {
    message = error.message
  }
  expect(message).toBe(
    'Error converting pgSetting: symbol needs to be of type string or number.',
  )
})

test('extra pgSettings that are booleans throw an error', async () => {
  const pgClient = { query: jest.fn(), release: jest.fn() }
  const pgPool = { connect: jest.fn(() => pgClient) }
  let message
  try {
    await withPostGraphileContext(
      {
        pgPool,
        jwtToken: jwt.sign({ aud: 'postgraphile' }, 'secret', {
          noTimestamp: true,
        }),
        jwtOptions: {
          secret: 'secret'
        },
        pgSettings: {
          'some.boolean': true,
        },
      },
      () => {},
    )
  } catch (error) {
    message = error.message
  }
  expect(message).toBe(
    'Error converting pgSetting: boolean needs to be of type string or number.',
  )
})

test('will set the default role if available', async () => {
  const pgClient = { query: jest.fn(), release: jest.fn() }
  const pgPool = { connect: jest.fn(() => pgClient) }
  await withPostGraphileContext(
    {
      pgPool,
      jwtOptions: {
        secret: 'secret'
      },
      pgDefaultRole: 'test_default_role',
    },
    () => {},
  )
  expect(pgClient.query.mock.calls).toEqual([
    ['begin'],
    [
      {
        text: 'select set_config($1, $2, true)',
        values: ['role', 'test_default_role'],
      },
    ],
    ['commit'],
  ])
})

test('will set the default role if no other role was provided in the JWT', async () => {
  const pgClient = { query: jest.fn(), release: jest.fn() }
  const pgPool = { connect: jest.fn(() => pgClient) }
  await withPostGraphileContext(
    {
      pgPool,
      jwtToken: jwt.sign({ aud: 'postgraphile', a: 1, b: 2, c: 3 }, 'secret', {
        noTimestamp: true,
      }),
      jwtOptions: {
        secret: 'secret'
      },
      pgDefaultRole: 'test_default_role',
    },
    () => {},
  )
  expect(pgClient.query.mock.calls).toEqual([
    ['begin'],
    [
      {
        text:
          'select set_config($1, $2, true), set_config($3, $4, true), set_config($5, $6, true), set_config($7, $8, true), set_config($9, $10, true)',
        values: [
          'role',
          'test_default_role',
          'jwt.claims.aud',
          'postgraphile',
          'jwt.claims.a',
          1,
          'jwt.claims.b',
          2,
          'jwt.claims.c',
          3,
        ],
      },
    ],
    ['commit'],
  ])
})

test('will set a role provided in the JWT', async () => {
  const pgClient = { query: jest.fn(), release: jest.fn() }
  const pgPool = { connect: jest.fn(() => pgClient) }
  await withPostGraphileContext(
    {
      pgPool,
      jwtToken: jwt.sign(
        { aud: 'postgraphile', a: 1, b: 2, c: 3, role: 'test_jwt_role' },
        'secret',
        { noTimestamp: true },
      ),
      jwtOptions: {
        secret: 'secret'
      }
    },
    () => {},
  )
  expect(pgClient.query.mock.calls).toEqual([
    ['begin'],
    [
      {
        text:
          'select set_config($1, $2, true), set_config($3, $4, true), set_config($5, $6, true), set_config($7, $8, true), set_config($9, $10, true), set_config($11, $12, true)',
        values: [
          'role',
          'test_jwt_role',
          'jwt.claims.aud',
          'postgraphile',
          'jwt.claims.a',
          1,
          'jwt.claims.b',
          2,
          'jwt.claims.c',
          3,
          'jwt.claims.role',
          'test_jwt_role',
        ],
      },
    ],
    ['commit'],
  ])
})

test('will set a role provided in the JWT superceding the default role', async () => {
  const pgClient = { query: jest.fn(), release: jest.fn() }
  const pgPool = { connect: jest.fn(() => pgClient) }
  await withPostGraphileContext(
    {
      pgPool,
      jwtToken: jwt.sign(
        { aud: 'postgraphile', a: 1, b: 2, c: 3, role: 'test_jwt_role' },
        'secret',
        { noTimestamp: true },
      ),
      jwtOptions: {
        secret: 'secret'
      },
      pgDefaultRole: 'test_default_role',
    },
    () => {},
  )
  expect(pgClient.query.mock.calls).toEqual([
    ['begin'],
    [
      {
        text:
          'select set_config($1, $2, true), set_config($3, $4, true), set_config($5, $6, true), set_config($7, $8, true), set_config($9, $10, true), set_config($11, $12, true)',
        values: [
          'role',
          'test_jwt_role',
          'jwt.claims.aud',
          'postgraphile',
          'jwt.claims.a',
          1,
          'jwt.claims.b',
          2,
          'jwt.claims.c',
          3,
          'jwt.claims.role',
          'test_jwt_role',
        ],
      },
    ],
    ['commit'],
  ])
})

test('will set a role provided in the JWT', async () => {
  const pgClient = { query: jest.fn(), release: jest.fn() }
  const pgPool = { connect: jest.fn(() => pgClient) }
  await withPostGraphileContext(
    {
      pgPool,
      jwtToken: jwt.sign(
        {
          aud: 'postgraphile',
          a: 1,
          b: 2,
          c: 3,
          some: { other: { path: 'test_deep_role' } },
        },
        'secret',
        { noTimestamp: true },
      ),
      jwtOptions: {
        secret: 'secret'
        role: ['some', 'other', 'path'],
      }
    },
    () => {},
  )
  expect(pgClient.query.mock.calls).toEqual([
    ['begin'],
    [
      {
        text:
          'select set_config($1, $2, true), set_config($3, $4, true), set_config($5, $6, true), set_config($7, $8, true), set_config($9, $10, true), set_config($11, $12, true)',
        values: [
          'role',
          'test_deep_role',
          'jwt.claims.aud',
          'postgraphile',
          'jwt.claims.a',
          1,
          'jwt.claims.b',
          2,
          'jwt.claims.c',
          3,
          'jwt.claims.some',
          { other: { path: 'test_deep_role' } },
        ],
      },
    ],
    ['commit'],
  ])
})

test('will set a role provided in the JWT superceding the default role', async () => {
  const pgClient = { query: jest.fn(), release: jest.fn() }
  const pgPool = { connect: jest.fn(() => pgClient) }
  await withPostGraphileContext(
    {
      pgPool,
      jwtToken: jwt.sign(
        {
          aud: 'postgraphile',
          a: 1,
          b: 2,
          c: 3,
          some: { other: { path: 'test_deep_role' } },
        },
        'secret',
        { noTimestamp: true },
      ),
      jwtOptions: {
        secret: 'secret'
        role: ['some', 'other', 'path']
      },
      pgDefaultRole: 'test_default_role',
    },
    () => {},
  )
  expect(pgClient.query.mock.calls).toEqual([
    ['begin'],
    [
      {
        text:
          'select set_config($1, $2, true), set_config($3, $4, true), set_config($5, $6, true), set_config($7, $8, true), set_config($9, $10, true), set_config($11, $12, true)',
        values: [
          'role',
          'test_deep_role',
          'jwt.claims.aud',
          'postgraphile',
          'jwt.claims.a',
          1,
          'jwt.claims.b',
          2,
          'jwt.claims.c',
          3,
          'jwt.claims.some',
          { other: { path: 'test_deep_role' } },
        ],
      },
    ],
    ['commit'],
  ])
})

describe('jwtOptions.verifyOptions', () => {
  let pgClient
  let pgPool
  beforeEach(() => {
    pgClient = { query: jest.fn(), release: jest.fn() }
    pgPool = { connect: jest.fn(() => pgClient) }
  })

  test('will throw an error if jwtOptions.audiences and jwtOptions.VerifyOptions.audiences are both provided', async () => {
    await expectHttpError(
      withPostGraphileContext(
        {
          pgPool,
          jwtToken: jwt.sign({ aud: 'postgrest' }, 'secret'),
          jwtOptions: {
            secret: 'secret',
            verifyOptions: { audience: 'another-audience' },
            audiences: ['some-other-audience']
          }
        },
        () => {},
      ),
      403,
      'Provide either \'jwtOptions.audiences\' or \'jwtOptions.verifyOptions.audience\' but not both',
    )
    expect(pgClient.query.mock.calls).toEqual([['begin'], ['commit']])
  })

  test('will succeed with both jwtOptions.audiences and jwtOptions.verifyOptions if jwtOptions.verifyOptions does not have an audience field', async () => {
    await withPostGraphileContext(
      {
        pgPool,
        jwtToken: jwt.sign({ aud: 'my-audience' }, 'secret', {
          noTimestamp: true,
          subject: 'my-subject',
        }),
        jwtOptions: {
          secret: 'secret',
          verifyOptions: { subject: 'my-subject' },
          audiences: ['my-audience'],
        }
      },
      () => {},
    )
    expect(pgClient.query.mock.calls).toEqual([
      ['begin'],
      [
        {
          text: 'select set_config($1, $2, true), set_config($3, $4, true)',
          values: [
            'jwt.claims.aud',
            'my-audience',
            'jwt.claims.sub',
            'my-subject',
          ],
        },
      ],
      ['commit'],
    ])
  })

  test('will throw an error if the JWT token does not have an appropriate audience', async () => {
    await expectHttpError(
      withPostGraphileContext(
        {
          pgPool,
          jwtToken: jwt.sign({ aud: 'postgrest' }, 'secret'),
          jwtOptions: {
            secret: 'secret',
            verifyOptions: { audience: 'another-audience' }
          }
        },
        () => {},
      ),
      403,
      'jwt audience invalid. expected: another-audience',
    )
    expect(pgClient.query.mock.calls).toEqual([['begin'], ['commit']])
  })

  test('will throw an error from a mismatched subject', async () => {
    await expectHttpError(
      withPostGraphileContext(
        {
          pgPool,
          jwtToken: jwt.sign({ aud: 'my-audience', sub: 'gorilla' }, 'secret'),
          jwtOptions: {
            secret: 'secret',
            verifyOptions: { subject: 'orangutan' },
            audiences: ['my-audience']
          }
        },
        () => {},
      ),
      403,
      'jwt subject invalid. expected: orangutan',
    )
    expect(pgClient.query.mock.calls).toEqual([['begin'], ['commit']])
  })

  test('will throw an error from an issuer array that does not match iss', async () => {
    await expectHttpError(
      withPostGraphileContext(
        {
          pgPool,
          jwtToken: jwt.sign(
            { aud: 'postgraphile', iss: 'alpha:nasa' },
            'secret',
          ),
          jwtOptions: {
            secret: 'secret',
            verifyOptions: { issuer: ['alpha:aliens', 'alpha:ufo'] }
          }
        },
        () => {},
      ),
      403,
      'jwt issuer invalid. expected: alpha:aliens,alpha:ufo',
    )
    expect(pgClient.query.mock.calls).toEqual([['begin'], ['commit']])
  })

  test('will default to an audience of [\'postgraphile\'] if no audience params are provided', async () => {
    await expectHttpError(
      withPostGraphileContext(
        {
          pgPool,
          jwtToken: jwt.sign({ aud: 'something' }, 'secret'),
          jwtOptions: {
            secret: 'secret'
          }
        },
        () => {},
      ),
      403,
      'jwt audience invalid. expected: postgraphile',
    )
    expect(pgClient.query.mock.calls).toEqual([['begin'], ['commit']])
  })
})
