import { QueryObserver } from '@tanstack/react-query';
import { mapValues } from 'lodash';

import { timeUnits } from '@/constants/time';

import { type RootStore } from '@/state/_store';
import { appQueryClient } from '@/state/appQueryClient';
import { setAllAssetsRaw } from '@/state/raw';

import metadataClient from '@/clients/metadataService';

import { loadableIdle } from '../lib/loadable';
import { mapLoadableData } from '../lib/mapLoadable';
import { logAbacusTsError } from '../logs';
import { queryResultToLoadable } from './lib/queryResultToLoadable';

export function setUpAssetsQuery(store: RootStore) {
  const observer = new QueryObserver(appQueryClient, {
    queryKey: ['metadata', 'assets'],
    queryFn: () => Promise.all([metadataClient.getAssetInfo(), metadataClient.getAssetPrices()]),
    refetchInterval: timeUnits.minute * 5,
    staleTime: timeUnits.minute * 5,
  });

  const unsubscribe = observer.subscribe((result) => {
    try {
      store.dispatch(
        setAllAssetsRaw(
          mapLoadableData(queryResultToLoadable(result), (map) => {
            const [info, prices] = map;
            return mapValues(info, (v, id) => ({ ...v, id, priceData: prices[id] }));
          })
        )
      );
    } catch (e) {
      logAbacusTsError('setUpAssetsQuery', 'Error handling result from react query', e, result);
    }
  });
  return () => {
    unsubscribe();
    store.dispatch(setAllAssetsRaw(loadableIdle()));
  };
}