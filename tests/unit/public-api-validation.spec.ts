import {BasicAuth, Iterator, QueryIterator, Trino} from '../../src';

const createAsyncIterator = <T>(value: T): AsyncIterableIterator<T> => {
  let done = false;

  return {
    [Symbol.asyncIterator]() {
      return this;
    },
    async next() {
      if (done) {
        return {value, done: true};
      }

      done = true;
      return {value, done: false};
    },
  };
};

describe('public api validation', () => {
  test('BasicAuth rejects empty usernames', () => {
    expect(() => new BasicAuth('')).toThrow('BasicAuth.username');
  });

  test('Trino.create rejects invalid connection options', () => {
    expect(() =>
      Trino.create({
        auth: {type: 'basic'} as unknown as BasicAuth,
      })
    ).toThrow('options.auth.username');

    expect(() =>
      Trino.create({
        session: {traceToken: 1} as unknown as Record<string, string>,
      })
    ).toThrow('options.session.traceToken');
  });

  test('Trino.query rejects invalid query inputs', async () => {
    const trino = Trino.create({});

    await expect(trino.query('')).rejects.toThrow('query');
    await expect(
      trino.query({
        query: 'select 1',
        extraHeaders: {traceToken: 1} as unknown as Record<string, string>,
      })
    ).rejects.toThrow('query.extraHeaders.traceToken');
  });

  test('Trino.queryInfo and Trino.cancel reject empty query ids', async () => {
    const trino = Trino.create({});

    await expect(trino.queryInfo('')).rejects.toThrow('queryId');
    await expect(trino.cancel('')).rejects.toThrow('queryId');
  });

  test('Iterator rejects invalid iterators and callbacks', async () => {
    expect(() => new Iterator({} as AsyncIterableIterator<number>)).toThrow(
      'iter'
    );

    const iter = new Iterator(createAsyncIterator(1));

    expect(() => iter.map(1 as unknown as (value: number) => number)).toThrow(
      'fn'
    );
    await expect(
      iter.forEach(1 as unknown as (value: number) => void)
    ).rejects.toThrow('fn');
    await expect(
      iter.fold(0, 1 as unknown as (value: number, acc: number) => number)
    ).rejects.toThrow('fn');
  });

  test('Iterator.map does not call fn on terminal result', async () => {
    const fn = jest.fn((v: number) => v * 2);
    const iter = new Iterator(createAsyncIterator(42));
    const mapped = iter.map(fn);

    const results: number[] = [];
    for await (const value of mapped) {
      results.push(value);
    }

    expect(results).toEqual([84]);
    expect(fn).toHaveBeenCalledTimes(1);
    expect(fn).toHaveBeenCalledWith(42);
  });

  test('QueryIterator rejects invalid constructor inputs', () => {
    expect(() => new QueryIterator({} as never, {id: 'query_1'})).toThrow(
      'client'
    );

    const trino = Trino.create({});
    const client = (trino as unknown as {client: unknown}).client;

    expect(() => new QueryIterator(client as never, {} as never)).toThrow(
      'queryResult.id'
    );
  });
});
