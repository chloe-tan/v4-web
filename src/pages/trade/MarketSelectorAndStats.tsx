import { shallowEqual } from 'react-redux';
import styled from 'styled-components';

import { layoutMixins } from '@/styles/layoutMixins';

import { VerticalSeparator } from '@/components/Separator';
import { MarketStatsDetails } from '@/views/MarketStatsDetails';
import { MarketsDropdown } from '@/views/MarketsDropdown';
import { UnlaunchedMarketStatsDetails } from '@/views/UnlaunchedMarketStatsDetails';

import { useAppSelector } from '@/state/appTypes';
import { getCurrentMarketAssetData } from '@/state/assetsSelectors';
import { getCurrentMarketDisplayId } from '@/state/perpetualsSelectors';

import { getDisplayableTickerFromMarket } from '@/lib/assetUtils';

export const MarketSelectorAndStats = ({
  className,
  launchableMarketId,
}: {
  className?: string;
  launchableMarketId?: string;
}) => {
  const { id = '' } = useAppSelector(getCurrentMarketAssetData, shallowEqual) ?? {};
  const currentMarketId = useAppSelector(getCurrentMarketDisplayId) ?? '';

  const displayableId = launchableMarketId
    ? getDisplayableTickerFromMarket(launchableMarketId)
    : launchableMarketId;

  return (
    <$Container className={className}>
      <MarketsDropdown
        launchableMarketId={launchableMarketId}
        currentMarketId={displayableId ?? currentMarketId}
        symbol={id}
      />

      <VerticalSeparator />

      {launchableMarketId ? (
        <UnlaunchedMarketStatsDetails launchableMarketId={launchableMarketId} />
      ) : (
        <MarketStatsDetails />
      )}
    </$Container>
  );
};
const $Container = styled.div`
  ${layoutMixins.container}

  display: grid;

  grid-template:
    var(--market-info-row-height)
    / auto;

  grid-auto-flow: column;
  justify-content: start;
  align-items: stretch;
`;
