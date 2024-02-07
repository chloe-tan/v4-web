import { useSelector } from 'react-redux';

import { AppTheme } from '@/state/configs';
import { getAppTheme } from '@/state/configsSelectors';

const ChaosLabsIcon: React.FC = () => {
  const appTheme = useSelector(getAppTheme);

  const fills = appTheme === AppTheme.Light ? ['#1482E5', '#000000'] : ['#1482E5', '#E5E9EB'];

  return (
    <svg width="91" height="17" viewBox="0 0 91 17" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path
        d="M13.4384 13.2558C13.3846 13.2931 13.3295 13.3283 13.2724 13.3615L11.4238 14.4385L4.17188 10.2149V6.61884L11.4198 2.39746L13.2724 3.47652C13.3376 3.51449 13.4007 3.55521 13.4619 3.59848L8.28233 6.60962V6.60225L6.20661 7.81644V9.05132L8.28233 10.2629V9.0364L14.4967 5.41709C14.5028 5.48788 14.5055 5.55928 14.5055 5.63112V7.80972L10.3675 10.2318V11.4757L13.4384 13.2558Z"
        fill={fills[0]}
      />
      <path
        d="M9.34397 1.18863L8.48587 0.688787C7.72318 0.244363 6.78308 0.244363 6.01972 0.688787L1.23307 3.47666C0.470044 3.92109 0 4.74241 0 5.63125V11.207C0 12.0958 0.470044 12.9172 1.23307 13.3616L6.01972 16.1495C6.78308 16.5939 7.72318 16.5939 8.48587 16.1495L9.348 15.6475L2.09628 11.4241V5.41158L2.09911 5.41323L2.09628 5.41L9.34397 1.18863Z"
        fill={fills[0]}
      />
      <path d="M62.777 12.3629V4.57764H64.1102V11.1154H67.7133V12.3629H62.777Z" fill={fills[1]} />
      <path
        d="M70.2932 10.5919L69.5029 12.3629H68.0797L71.5585 4.57764H72.9817L76.4605 12.3629H75.0373L74.2464 10.5919H70.2932ZM73.7041 9.37795L72.2701 6.17032L70.8355 9.37795H73.7041Z"
        fill={fills[1]}
      />
      <path
        d="M81.0141 12.3629H77.5581V4.57764H80.6304C81.1646 4.57764 81.6242 4.64075 82.0079 4.76698C82.3997 4.8932 82.6893 5.06398 82.8781 5.27931C83.2396 5.68026 83.4197 6.1332 83.4197 6.6381C83.4197 7.24693 83.2242 7.69991 82.8324 7.99692C82.6893 8.10087 82.5918 8.16767 82.5388 8.19737C82.4863 8.21968 82.3923 8.26047 82.2565 8.31987C82.7464 8.42382 83.1341 8.64289 83.4197 8.97699C83.7134 9.3037 83.8605 9.71213 83.8605 10.2021C83.8605 10.7442 83.6724 11.2231 83.2961 11.6389C82.8512 12.1215 82.0912 12.3629 81.0141 12.3629ZM78.8906 7.80756H80.5847C81.5489 7.80756 82.0307 7.48454 82.0307 6.83858C82.0307 6.46732 81.9138 6.20002 81.6806 6.03667C81.4468 5.87331 81.086 5.79164 80.5961 5.79164H78.8906V7.80756ZM78.8906 11.1489H80.9805C81.4697 11.1489 81.8426 11.0746 82.0986 10.9261C82.362 10.7701 82.4937 10.4806 82.4937 10.0574C82.4937 9.3668 81.9326 9.02154 80.8111 9.02154H78.8906V11.1489Z"
        fill={fills[1]}
      />
      <path
        d="M87.9162 5.60121C87.5325 5.60121 87.216 5.67917 86.9674 5.8351C86.7194 5.99103 86.5951 6.22863 86.5951 6.54791C86.5951 6.85977 86.7194 7.1011 86.9674 7.27185C87.216 7.4352 87.7435 7.61341 88.5492 7.80647C89.3623 7.99953 89.9724 8.27053 90.379 8.61949C90.7929 8.96851 90.9999 9.48452 90.9999 10.1676C90.9999 10.8433 90.7405 11.3928 90.2204 11.816C89.701 12.2393 89.0196 12.4509 88.1763 12.4509C86.9412 12.4509 85.8459 12.0314 84.8896 11.1923L85.7249 10.201C86.5232 10.8842 87.3518 11.2257 88.2099 11.2257C88.6393 11.2257 88.9779 11.1366 89.2266 10.9584C89.4826 10.7728 89.6109 10.5314 89.6109 10.2345C89.6109 9.93003 89.49 9.69619 89.2494 9.53283C89.0156 9.36202 88.609 9.20981 88.0291 9.07616C87.4499 8.93511 87.0091 8.80885 86.708 8.6975C86.407 8.5787 86.1395 8.42643 85.9057 8.24083C85.4393 7.89188 85.2055 7.35726 85.2055 6.63702C85.2055 5.91678 85.4689 5.36361 85.9964 4.9775C86.5306 4.58397 87.1898 4.38721 87.9727 4.38721C88.4773 4.38721 88.9779 4.46889 89.4752 4.63224C89.9724 4.79558 90.4012 5.02577 90.7627 5.32277L90.0511 6.31402C89.8179 6.10612 89.5014 5.93534 89.1022 5.80169C88.7031 5.66804 88.308 5.60121 87.9162 5.60121Z"
        fill={fills[1]}
      />
      <path
        d="M24.047 4.38721C22.8629 4.38721 21.861 4.77008 21.0648 5.54419L21.0634 5.54519C20.2745 6.31948 19.8807 7.2916 19.8807 8.43967C19.8807 9.58585 20.2665 10.5517 21.0433 11.3136L21.0439 11.3146C21.8268 12.0745 22.8072 12.4509 23.9643 12.4509C25.1463 12.4509 26.1536 11.9892 26.9707 11.0839L27.1609 10.8729L25.9722 9.65318L25.7558 9.85645C25.442 10.1501 25.1524 10.3555 24.8869 10.4827C24.6336 10.5973 24.3191 10.6603 23.9334 10.6603C23.3434 10.6603 22.8361 10.4504 22.3966 10.0177C21.9686 9.58323 21.7542 9.05029 21.7542 8.39841C21.7542 7.73954 21.9719 7.22084 22.4006 6.81607L22.402 6.81454C22.8367 6.39839 23.371 6.18802 24.0261 6.18802C24.4071 6.18802 24.7216 6.24839 24.9776 6.35892L24.9797 6.35987C25.2437 6.47129 25.5394 6.67559 25.866 6.98947L26.0904 7.20438L27.2583 5.92696L27.0729 5.72256C26.2665 4.83489 25.2511 4.38721 24.047 4.38721Z"
        fill={fills[1]}
      />
      <path
        fillRule="evenodd"
        clipRule="evenodd"
        d="M47.6624 4.38721C46.5167 4.38721 45.5396 4.77222 44.7521 5.54468C43.9625 6.31199 43.5687 7.27749 43.5687 8.41904C43.5687 9.55454 43.9632 10.5194 44.7514 11.2929L44.7527 11.2939C45.5403 12.0594 46.5173 12.4406 47.6624 12.4406C48.8074 12.4406 49.7845 12.0594 50.572 11.2939L50.5734 11.2929C51.3616 10.5194 51.756 9.55454 51.756 8.41904C51.756 7.27749 51.3623 6.312 50.5727 5.54469C49.7851 4.77223 48.8081 4.38721 47.6624 4.38721ZM45.4207 8.41904C45.4207 7.76676 45.6364 7.22501 46.0671 6.77549C46.5039 6.32689 47.0294 6.10561 47.6624 6.10561C48.2954 6.10561 48.8168 6.32697 49.2462 6.77466L49.2476 6.77617C49.6857 7.22615 49.9034 7.7677 49.9034 8.41904C49.9034 9.06265 49.6864 9.60104 49.2476 10.0516L49.2462 10.0531C48.8168 10.5008 48.2954 10.7222 47.6624 10.7222C47.0294 10.7222 46.5039 10.5009 46.0671 10.0523C45.6357 9.60218 45.4207 9.06359 45.4207 8.41904Z"
        fill={fills[1]}
      />
      <path
        d="M55.2113 4.38721C54.4439 4.38721 53.7767 4.58367 53.2277 4.99291C52.6605 5.41417 52.3843 6.02137 52.3843 6.77092C52.3843 7.50415 52.6222 8.09878 53.1396 8.49282C53.3768 8.68366 53.6463 8.83835 53.9446 8.95789L53.9514 8.96024C54.2423 9.06951 54.6576 9.18959 55.1898 9.32096L55.1938 9.32176C55.7153 9.4438 56.0345 9.57362 56.1944 9.69243L56.1991 9.69565L56.2038 9.69874C56.3355 9.78966 56.402 9.90967 56.402 10.098C56.402 10.2701 56.3362 10.4048 56.1756 10.523C56.0177 10.6376 55.7791 10.7119 55.4277 10.7119C54.7335 10.7119 54.0461 10.4338 53.36 9.83838L53.1262 9.63551L51.9791 11.0155L52.1975 11.2103C53.1228 12.0336 54.1933 12.4509 55.3968 12.4509C56.2179 12.4509 56.9134 12.2409 57.4537 11.7944C57.9987 11.3443 58.2748 10.7498 58.2748 10.0363C58.2748 9.34239 58.0652 8.77028 57.6029 8.37509C57.1809 8.00799 56.5721 7.74216 55.808 7.55804C55.4458 7.47001 55.1515 7.38669 54.923 7.3084C54.6926 7.22931 54.5461 7.16104 54.4648 7.10769C54.3257 7.00954 54.2571 6.88184 54.2571 6.68852C54.2571 6.48456 54.3277 6.36719 54.4574 6.28486C54.6227 6.17969 54.8498 6.11592 55.1596 6.11592C55.4814 6.11592 55.8087 6.17147 56.144 6.28523C56.4813 6.39984 56.73 6.54009 56.9033 6.69703L57.1567 6.92574L58.1646 5.50194L57.9496 5.32269C57.5874 5.02123 57.1621 4.79104 56.6769 4.62937C56.1937 4.46839 55.7052 4.38721 55.2113 4.38721Z"
        fill={fills[1]}
      />
      <path
        d="M29.7507 4.56055H27.9297V12.3667H29.7507V9.42066H32.7195V12.3667H34.5406V4.56055H32.7195V7.68166H29.7507V4.56055Z"
        fill={fills[1]}
      />
      <path
        fillRule="evenodd"
        clipRule="evenodd"
        d="M40.3586 4.56055H38.6659L35.2261 12.3667H37.1862L37.9072 10.7289H41.1173L41.8383 12.3667H43.7984L40.3586 4.56055ZM38.6686 9.00014L39.5126 7.08737L40.3559 9.00014H38.6686Z"
        fill={fills[1]}
      />
    </svg>
  );
};

export default ChaosLabsIcon;
