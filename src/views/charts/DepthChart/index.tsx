import { useCallback, useEffect, useMemo, useState } from 'react';

import { OrderSide } from '@dydxprotocol/v4-client-js';
import { curveStepAfter } from '@visx/curve';
import { LinearGradient } from '@visx/gradient';
import { Point } from '@visx/point';
import {
  AreaSeries,
  Axis,
  DataProvider,
  EventEmitterProvider,
  Grid,
  LineSeries,
  buildChartTheme,
  darkTheme,
  type EventHandlerParams,
} from '@visx/xychart';
import { shallowEqual } from 'react-redux';
import styled, { keyframes } from 'styled-components';

import {
  DepthChartDatum,
  DepthChartPoint,
  DepthChartSeries,
  SERIES_KEY_FOR_ORDER_SIDE,
} from '@/constants/charts';
import { StringGetterFunction } from '@/constants/localization';

import { useOrderbookValuesForDepthChart } from '@/hooks/Orderbook/useOrderbookValues';
import { useBreakpoints } from '@/hooks/useBreakpoints';
import { useLocaleSeparators } from '@/hooks/useLocaleSeparators';

import { LoadingSpace } from '@/components/Loading/LoadingSpinner';
import { OutputType, formatNumberOutput } from '@/components/Output';
import { AxisLabelOutput } from '@/components/visx/AxisLabelOutput';
import Tooltip from '@/components/visx/XYChartTooltipWithBounds';
import { XYChartWithPointerEvents } from '@/components/visx/XYChartWithPointerEvents';

import { useAppSelector } from '@/state/appTypes';
import { getCurrentMarketAssetData } from '@/state/assetsSelectors';
import { getCurrentMarketConfig } from '@/state/perpetualsSelectors';

import { MustBigNumber } from '@/lib/numbers';

import { DepthChartTooltipContent } from './Tooltip';

// @ts-ignore
const theme = buildChartTheme({
  ...darkTheme,
  colors: ['var(--color-positive)', 'var(--color-negative)', 'var(--color-layer-6)'], // categorical colors, mapped to series via `dataKey`s
});

const clamp = (n: number, min: number, max: number) => Math.max(min, Math.min(max, n));
const lerp = (percent: number, from: number, to: number) => from + percent * (to - from);

export const DepthChart = ({
  onChartClick,
  stringGetter,
  selectedLocale,
}: {
  onChartClick?: (point: { side: OrderSide; price: number; size: number }) => void;
  stringGetter: StringGetterFunction;
  selectedLocale: string;
}) => {
  // Context

  const { isMobile } = useBreakpoints();
  const { decimal: decimalSeparator, group: groupSeparator } = useLocaleSeparators();

  // Chart data
  const { id = '' } = useAppSelector(getCurrentMarketAssetData, shallowEqual) ?? {};
  const { stepSizeDecimals, tickSizeDecimals } =
    useAppSelector(getCurrentMarketConfig, shallowEqual) ?? {};

  const { bids, asks, lowestBid, highestBid, lowestAsk, highestAsk, midMarketPrice, orderbook } =
    useOrderbookValuesForDepthChart();

  // Chart state

  const [isPointerPressed, setIsPointerPressed] = useState(false);
  const [chartPointAtPointer, setChartPointAtPointer] = useState<DepthChartPoint>();

  const isEditingOrder = Boolean(isPointerPressed && chartPointAtPointer);

  const [zoomDomain, setZoomDomain] = useState<undefined | number>();

  useEffect(() => {
    if (!midMarketPrice) {
      setZoomDomain(undefined);
    } else if (!zoomDomain) {
      setZoomDomain(
        // Start by showing smallest of:
        Math.min(
          // Mid-market price ± 1.5%
          midMarketPrice * 0.015,
          // Mid-market price ± halfway to lowest bid
          (midMarketPrice - (lowestBid?.price ?? 0)) / 2,
          // Mid-market price ± halfway to highest ask
          ((highestAsk?.price ?? midMarketPrice) - midMarketPrice) / 2
        )
      );
    }
  }, [midMarketPrice]);

  // Computations

  const { domain, range } = useMemo(() => {
    if (!(zoomDomain && midMarketPrice && asks.length && bids.length))
      return { domain: [0, 0] as const, range: [0, 0] as const };

    const newDomain = [
      clamp(midMarketPrice - zoomDomain, 0, highestBid?.price ?? 0),
      clamp(midMarketPrice + zoomDomain, lowestAsk?.price ?? 0, highestAsk?.price ?? 0),
    ] as const;

    const newRange = [
      0,
      [...bids, ...asks]
        .filter((datum) => datum.price >= newDomain[0] && datum.price <= newDomain[1])
        .map((datum) => datum.depth ?? 0)
        .reduce((a, b) => Math.max(a, b), 0),
    ] as const;

    return { domain: newDomain, range: newRange };
  }, [orderbook, zoomDomain]);

  const getChartPoint = useCallback(
    (point: Point | EventHandlerParams<object>) => {
      let price;
      let size;
      if (point instanceof Point) {
        const { x, y } = point;
        price = x;
        size = y;
      } else {
        const { svgPoint: { x, y } = {} } = point;
        price = x ?? 0;
        size = y ?? 0;
      }

      return {
        side: MustBigNumber(price).lt(midMarketPrice!) ? OrderSide.BUY : OrderSide.SELL,
        price,
        size,
      } satisfies DepthChartPoint;
    },
    [midMarketPrice]
  );

  const formatNumber = useCallback(
    (n: number) =>
      formatNumberOutput(n, OutputType.Number, {
        decimalSeparator,
        groupSeparator,
        selectedLocale,
        fractionDigits: tickSizeDecimals,
      }),
    [decimalSeparator, groupSeparator, selectedLocale, tickSizeDecimals]
  );

  // Render conditions

  if (!(zoomDomain && midMarketPrice && asks.length && bids.length))
    return <LoadingSpace id="depth-chart-loading" />;

  // Events

  const onDepthChartZoom = ({
    deltaY,
    wheelDelta = deltaY,
  }: React.WheelEvent & { wheelDelta?: number }) => {
    setZoomDomain(
      clamp(
        Math.max(
          1e-320,
          Math.min(Number.MAX_SAFE_INTEGER, zoomDomain * Math.exp(wheelDelta / 1000))
        ),
        Math.min(
          midMarketPrice - (highestBid?.price ?? 0),
          (lowestAsk?.price ?? 0) - midMarketPrice
        ),
        Math.max(
          midMarketPrice - (lowestBid?.price ?? 0),
          (highestAsk?.price ?? 0) - midMarketPrice
        )
      )
    );
  };

  return (
    <$Container onWheel={onDepthChartZoom}>
      <DataProvider
        theme={theme}
        xScale={{
          type: 'linear',
          clamp: false,
          nice: false,
          zero: false,
          // Add 2% left and right "padding"
          domain: [lerp(-0.02, ...domain), lerp(1.02, ...domain)],
        }}
        yScale={{
          type: 'linear',
          clamp: true,
          nice: true,
          zero: true,
          // Add 5% top "padding"
          domain: [range[0], lerp(1.05, ...range)],
        }}
      >
        <EventEmitterProvider>
          <XYChartWithPointerEvents
            margin={{
              left: 0,
              right: 0,
              top: 0,
              bottom: 32,
            }}
            onPointerUp={(point) => point && onChartClick?.(getChartPoint(point))}
            onPointerMove={(point) => point && setChartPointAtPointer(getChartPoint(point))}
            onPointerPressedChange={(pointerPressed) => setIsPointerPressed(pointerPressed)}
          >
            <Axis orientation="bottom" numTicks={4} tickFormat={formatNumber} />

            <Grid
              numTicks={4}
              lineStyle={{
                stroke: 'var(--color-border)',
                strokeWidth: 'var(--border-width)',
              }}
            />

            <AreaSeries
              dataKey={DepthChartSeries.Bids}
              data={
                bids.length > 0
                  ? [
                      {
                        ...highestBid!,
                        depth: 0,
                      },
                      ...bids,
                      {
                        ...lowestBid!,
                        price: 0,
                      },
                    ].reverse()
                  : []
              }
              xAccessor={(datum: DepthChartDatum | undefined) => datum?.price ?? 0}
              yAccessor={(datum: DepthChartDatum | undefined) => datum?.depth ?? 0}
              curve={curveStepAfter}
              lineProps={{ strokeWidth: 1.5 }}
              fillOpacity={0.2}
              fill="url(#LinearGradient-Bids)"
            />
            <LinearGradient
              id="LinearGradient-Bids"
              from="var(--color-positive)"
              to="var(--color-positive)"
              toOpacity={0.4}
            />

            <AreaSeries
              dataKey={DepthChartSeries.Asks}
              data={
                asks.length > 0
                  ? [
                      {
                        ...lowestAsk!,
                        depth: 0,
                      },
                      ...asks,
                    ]
                  : []
              }
              xAccessor={(datum: DepthChartDatum) => datum.price}
              yAccessor={(datum: DepthChartDatum) => datum.depth}
              curve={curveStepAfter}
              lineProps={{ strokeWidth: 1.5 }}
              fillOpacity={0.2}
              fill="url(#LinearGradient-Asks)"
            />
            <LinearGradient
              id="LinearGradient-Asks"
              from="var(--color-negative)"
              to="var(--color-negative)"
              toOpacity={0.4}
            />

            <LineSeries
              dataKey={DepthChartSeries.MidMarket}
              data={[
                {
                  price: midMarketPrice,
                  depth: lerp(1.2, ...range),
                },
                {
                  price: midMarketPrice,
                  depth: lerp(0.5, ...range),
                },
                {
                  price: midMarketPrice,
                  depth: lerp(-0.1, ...range),
                },
              ]}
              strokeWidth={0.25}
              xAccessor={(datum) => datum.price}
              yAccessor={(datum) => datum.depth}
            />

            <Tooltip<DepthChartDatum>
              unstyled
              applyPositionStyle
              showDatumGlyph={!isEditingOrder}
              glyphStyle={{ radius: 6, opacity: 0.8 }}
              showVerticalCrosshair
              verticalCrosshairStyle={{ strokeWidth: 1, strokeDasharray: '5 5', opacity: 0.7 }}
              snapCrosshairToDatumX={!isEditingOrder}
              renderXAxisLabel={({ tooltipData }) => (
                <AxisLabelOutput
                  type={OutputType.Fiat}
                  value={
                    isEditingOrder && chartPointAtPointer
                      ? chartPointAtPointer.price
                      : tooltipData!.nearestDatum?.datum.price
                  }
                  useGrouping={false}
                  accentColor={
                    {
                      [DepthChartSeries.Asks]: 'var(--color-negative)',
                      [DepthChartSeries.Bids]: 'var(--color-positive)',
                      [DepthChartSeries.MidMarket]: 'var(--color-layer-6)',
                    }[
                      isEditingOrder && chartPointAtPointer
                        ? SERIES_KEY_FOR_ORDER_SIDE[chartPointAtPointer.side]
                        : (tooltipData!.nearestDatum?.key as DepthChartSeries)
                    ]
                  }
                  tw="shadow-[0_0_0.5rem_var(--color-layer-2)]"
                />
              )}
              showHorizontalCrosshair
              horizontalCrosshairStyle={{ strokeWidth: 1, strokeDasharray: '5 5', opacity: 0.7 }}
              snapCrosshairToDatumY={false}
              renderYAxisLabel={({ tooltipData }) =>
                (isEditingOrder || tooltipData!.nearestDatum?.datum.depth) && (
                  <$YAxisLabelOutput
                    type={OutputType.Asset}
                    value={
                      isEditingOrder && chartPointAtPointer
                        ? chartPointAtPointer.size
                        : tooltipData!.nearestDatum?.datum.depth
                    }
                    tag={id}
                    accentColor={
                      {
                        [DepthChartSeries.Asks]: 'var(--color-negative)',
                        [DepthChartSeries.Bids]: 'var(--color-positive)',
                        [DepthChartSeries.MidMarket]: 'var(--color-layer-6)',
                      }[
                        isEditingOrder && chartPointAtPointer
                          ? SERIES_KEY_FOR_ORDER_SIDE[chartPointAtPointer.side]
                          : (tooltipData!.nearestDatum?.key as DepthChartSeries)
                      ]
                    }
                  />
                )
              }
              snapTooltipToDatumX={!isEditingOrder}
              snapTooltipToDatumY={isEditingOrder ? false : isMobile}
              renderTooltip={({ tooltipData, colorScale }) =>
                chartPointAtPointer && (
                  <DepthChartTooltipContent
                    {...{
                      tooltipData,
                      colorScale,
                      isEditingOrder,
                      chartPointAtPointer,
                      stringGetter,
                      selectedLocale,
                      stepSizeDecimals,
                      tickSizeDecimals,
                    }}
                  />
                )
              }
            />
          </XYChartWithPointerEvents>
        </EventEmitterProvider>
      </DataProvider>
    </$Container>
  );
};

const $Container = styled.div`
  width: 0;
  min-width: 100%;
  height: 0;
  min-height: 100%;
  overflow: hidden;

  font-size: 0.75rem;

  transform-style: flat;

  cursor: crosshair;
  user-select: none;

  text {
    font-feature-settings: var(--fontFeature-monoNumbers);
  }

  @media (prefers-reduced-motion: no-preference) {
    [data-state='open'] {
      animation: ${keyframes`
        from {
          opacity: 0;
        }
      `} 0.1s var(--ease-out-expo);
    }
    /* [data-state="closed"] { */
    &:not(:hover) [data-state] {
      animation: ${keyframes`
        to {
          opacity: 0;
        }
      `} 0.2s 0.3s var(--ease-out-expo) forwards;
    }
  }
`;

const $YAxisLabelOutput = styled(AxisLabelOutput)`
  --axisLabel-offset: 0.5rem;

  [data-side='left'] & {
    translate: calc(50% + var(--axisLabel-offset)) 0;
  }

  [data-side='right'] & {
    translate: calc(-50% - var(--axisLabel-offset)) 0;
  }
`;
