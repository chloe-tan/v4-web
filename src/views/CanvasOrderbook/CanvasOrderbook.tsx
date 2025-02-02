import { forwardRef, useCallback, useMemo, useRef } from 'react';

import { shallowEqual } from 'react-redux';
import styled, { css } from 'styled-components';
import tw from 'twin.macro';

import { AbacusInputTypes, Nullable, type PerpetualMarketOrderbookLevel } from '@/constants/abacus';
import { STRING_KEYS } from '@/constants/localization';
import { SMALL_USD_DECIMALS, USD_DECIMALS } from '@/constants/numbers';
import { ORDERBOOK_MAX_ROWS_PER_SIDE, ORDERBOOK_ROW_HEIGHT } from '@/constants/orderbook';

import { useCenterOrderbook } from '@/hooks/Orderbook/useCenterOrderbook';
import { useDrawOrderbook } from '@/hooks/Orderbook/useDrawOrderbook';
import { useOrderbookMiddleRowScrollListener } from '@/hooks/Orderbook/useOrderbookMiddleRowScrollListener';
import { useCalculateOrderbookData } from '@/hooks/Orderbook/useOrderbookValues';
import { useStringGetter } from '@/hooks/useStringGetter';

import { Canvas } from '@/components/Canvas';
import { DisplayUnitTag } from '@/components/DisplayUnitTag';
import { LoadingSpace } from '@/components/Loading/LoadingSpinner';
import { Tag } from '@/components/Tag';

import { useAppDispatch, useAppSelector } from '@/state/appTypes';
import { getSelectedDisplayUnit } from '@/state/appUiConfigsSelectors';
import { setTradeFormInputs } from '@/state/inputs';
import { getCurrentInput } from '@/state/inputsSelectors';
import {
  getCurrentMarketConfig,
  getCurrentMarketData,
  getCurrentMarketId,
} from '@/state/perpetualsSelectors';

import { MustBigNumber } from '@/lib/numbers';

import { OrderbookControls } from './OrderbookControls';
import { OrderbookMiddleRow, OrderbookRow } from './OrderbookRow';

type ElementProps = {
  className?: string;
  rowsPerSide?: number;
  layout?: 'vertical' | 'horizontal';
};

type StyleProps = {
  histogramSide?: 'left' | 'right';
  hideHeader?: boolean;
};

export const CanvasOrderbook = forwardRef(
  (
    {
      className,
      histogramSide = 'right',
      hideHeader = false,
      layout = 'vertical',
      rowsPerSide = ORDERBOOK_MAX_ROWS_PER_SIDE,
    }: ElementProps & StyleProps,
    ref: React.ForwardedRef<HTMLDivElement>
  ) => {
    const { asks, bids, hasOrderbook, histogramRange, currentGrouping } = useCalculateOrderbookData(
      {
        rowsPerSide,
      }
    );

    const stringGetter = useStringGetter();
    const currentMarket = useAppSelector(getCurrentMarketId) ?? '';
    const currentMarketConfig = useAppSelector(getCurrentMarketConfig, shallowEqual);
    const { assetId: id } = useAppSelector(getCurrentMarketData, shallowEqual) ?? {};

    const { tickSizeDecimals = USD_DECIMALS } = currentMarketConfig ?? {};

    /**
     * Slice asks and bids to rowsPerSide using empty rows
     */
    const { asksSlice, bidsSlice } = useMemo(() => {
      const emptyAskRows =
        asks.length < rowsPerSide
          ? new Array<undefined>(rowsPerSide - asks.length).fill(undefined)
          : [];

      const newAsksSlice: Array<PerpetualMarketOrderbookLevel | undefined> = [
        ...emptyAskRows,
        ...asks.reverse(),
      ];

      const emptyBidRows =
        bids.length < rowsPerSide
          ? new Array<undefined>(rowsPerSide - bids.length).fill(undefined)
          : [];
      const newBidsSlice: Array<PerpetualMarketOrderbookLevel | undefined> = [
        ...bids,
        ...emptyBidRows,
      ];

      return {
        asksSlice: layout === 'horizontal' ? newAsksSlice : newAsksSlice.reverse(),
        bidsSlice: newBidsSlice,
      };
    }, [asks, bids, layout, rowsPerSide]);

    const orderbookRef = useRef<HTMLDivElement>(null);
    useCenterOrderbook({
      orderbookRef,
      marketId: currentMarket,
      disabled: layout === 'horizontal',
    });

    /**
     * Display top or bottom middleRow when center middleRow is off screen
     */
    const orderbookMiddleRowRef = useRef<HTMLDivElement>(null);

    const displaySide = useOrderbookMiddleRowScrollListener({
      orderbookRef,
      orderbookMiddleRowRef,
    });

    /**
     * Row action
     */
    const currentInput = useAppSelector(getCurrentInput);
    const dispatch = useAppDispatch();
    const onRowAction = useCallback(
      (price: Nullable<number>) => {
        if (currentInput === AbacusInputTypes.Trade && price) {
          // avoid scientific notation for when converting small number to string
          dispatch(
            setTradeFormInputs({
              limitPriceInput: MustBigNumber(price).toFixed(tickSizeDecimals ?? SMALL_USD_DECIMALS),
            })
          );
        }
      },
      [dispatch, currentInput, tickSizeDecimals]
    );

    const displayUnit = useAppSelector(getSelectedDisplayUnit);

    const { canvasRef: asksCanvasRef } = useDrawOrderbook({
      data: asksSlice,
      histogramRange,
      histogramSide,
      displayUnit,
      side: 'ask',
    });

    const { canvasRef: bidsCanvasRef } = useDrawOrderbook({
      data: bidsSlice,
      histogramRange,
      histogramSide: layout === 'horizontal' ? 'left' : histogramSide,
      displayUnit,
      side: 'bid',
    });

    const asksOrderbook = (
      <$OrderbookSideContainer $side="asks" $rows={rowsPerSide}>
        <$HoverRows $bottom={layout !== 'horizontal'}>
          {[...asksSlice].reverse().map((row: PerpetualMarketOrderbookLevel | undefined, idx) =>
            row ? (
              <$Row
                // eslint-disable-next-line react/no-array-index-key
                key={idx}
                title={`${row.price}`}
                onClick={() => {
                  onRowAction(row.price);
                }}
              />
            ) : (
              // eslint-disable-next-line react/no-array-index-key
              <$Row key={idx} />
            )
          )}
        </$HoverRows>
        <$OrderbookCanvas ref={asksCanvasRef} width="100%" height="100%" />
      </$OrderbookSideContainer>
    );
    const bidsOrderbook = (
      <$OrderbookSideContainer $side="bids" $rows={rowsPerSide}>
        <$HoverRows>
          {bidsSlice.map((row: PerpetualMarketOrderbookLevel | undefined, idx) =>
            row ? (
              <$Row
                // eslint-disable-next-line react/no-array-index-key
                key={idx}
                title={`${row.price}`}
                onClick={
                  row.price
                    ? () => {
                        onRowAction(row.price);
                      }
                    : undefined
                }
              />
            ) : (
              // eslint-disable-next-line react/no-array-index-key
              <$Row key={idx} />
            )
          )}
        </$HoverRows>
        <$OrderbookCanvas ref={bidsCanvasRef} width="100%" height="100%" />
      </$OrderbookSideContainer>
    );

    return (
      <div className={className} ref={ref} tw="flex flex-1 flex-col overflow-hidden">
        <$OrderbookContent $isLoading={!hasOrderbook}>
          {!hideHeader && <OrderbookControls assetId={id} grouping={currentGrouping} />}
          {!hideHeader && (
            <$OrderbookRow tw="h-1.75 text-color-text-0">
              <span>
                {stringGetter({ key: STRING_KEYS.PRICE })} <Tag>USD</Tag>
              </span>
              <span>
                {stringGetter({ key: STRING_KEYS.SIZE })}{' '}
                <DisplayUnitTag assetId={id} entryPoint="orderbookAssetTag" />
              </span>
              <span>
                {stringGetter({ key: STRING_KEYS.TOTAL })}{' '}
                <DisplayUnitTag assetId={id} entryPoint="orderbookAssetTag" />
              </span>
            </$OrderbookRow>
          )}

          {(displaySide === 'top' || layout === 'horizontal') && (
            <$OrderbookMiddleRow
              side="top"
              tickSizeDecimals={tickSizeDecimals}
              isHeader={layout === 'horizontal'}
            />
          )}
          {layout === 'vertical' ? (
            <>
              <div ref={orderbookRef} tw="flex flex-1 flex-col justify-center overflow-y-auto">
                {asksOrderbook}
                <OrderbookMiddleRow
                  tickSizeDecimals={tickSizeDecimals}
                  ref={orderbookMiddleRowRef}
                />
                {bidsOrderbook}
              </div>
              {displaySide === 'bottom' && (
                <$OrderbookMiddleRow side="bottom" tickSizeDecimals={tickSizeDecimals} />
              )}
            </>
          ) : (
            <div tw="grid grid-cols-[1fr_1fr] overflow-y-auto">
              {asksOrderbook}
              {bidsOrderbook}
            </div>
          )}
        </$OrderbookContent>
        {!hasOrderbook && <LoadingSpace id="canvas-orderbook" />}
      </div>
    );
  }
);
const $OrderbookContent = styled.div<{ $isLoading?: boolean }>`
  min-height: 100%;
  max-height: 100%;
  display: flex;
  flex-direction: column;
  position: relative;
  ${({ $isLoading }) => $isLoading && 'flex: 1;'}
`;

const $OrderbookSideContainer = styled.div<{ $side: 'bids' | 'asks'; $rows: number }>`
  ${({ $rows }) => css`
    min-height: calc(${$rows} * ${ORDERBOOK_ROW_HEIGHT}px);
  `}
  ${({ $side }) => css`
    --accent-color: ${$side === 'bids' ? 'var(--color-positive)' : 'var(--color-negative)'};
  `}
  position: relative;
`;

const $OrderbookCanvas = styled(Canvas)`
  width: 100%;
  height: 100%;
  position: absolute;
  top: 0;
  right: 0;
  pointer-events: none;
  font-feature-settings: var(--fontFeature-monoNumbers);
`;

const $HoverRows = styled.div<{ $bottom?: boolean }>`
  position: absolute;
  width: 100%;

  ${({ $bottom }) => $bottom && 'bottom: 0;'}
`;

const $OrderbookRow = styled(OrderbookRow)`
  border-top: var(--border);
  border-bottom: var(--border);
`;

const $Row = styled(OrderbookRow)<{ onClick?: () => void }>`
  ${({ onClick }) =>
    onClick
      ? css`
          cursor: pointer;

          &:hover {
            background-color: var(--color-layer-4);
            filter: darkness(0.1);
          }
        `
      : css`
          cursor: default;
        `}
`;

const $OrderbookMiddleRow = tw(OrderbookMiddleRow)`absolute`;
