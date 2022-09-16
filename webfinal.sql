-- phpMyAdmin SQL Dump
-- version 5.1.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1:3307
-- Generation Time: Sep 29, 2021 at 07:00 AM
-- Server version: 10.4.20-MariaDB
-- PHP Version: 8.0.9

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `webfinal`
--

-- --------------------------------------------------------

--
-- Table structure for table `accounts_profile`
--

CREATE TABLE `accounts_profile` (
  `id` bigint(20) NOT NULL,
  `firstname` varchar(50) NOT NULL,
  `lastname` varchar(50) NOT NULL,
  `username` varchar(50) NOT NULL,
  `email` varchar(254) NOT NULL,
  `phone` varchar(10) NOT NULL,
  `profile_pic` varchar(100) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `created_date` datetime(6) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `accounts_profile`
--

INSERT INTO `accounts_profile` (`id`, `firstname`, `lastname`, `username`, `email`, `phone`, `profile_pic`, `user_id`, `created_date`) VALUES
(1, 'Ruby', 'Kakshapati', 'Ruby', 'manisha.basukala012@gmail.com', '8766336789', 'static/profiles/o1.webp', 2, '2021-09-21 08:13:58.139795'),
(2, '', '', 'admin', 'manisha.basukala012@gmail.com', '', 'static/images/sample_user.jpg', 4, '2021-09-21 17:43:12.424430'),
(3, 'Richa', 'Sharma', 'Richa', 'basukala012@gmail.com', '8788909876', 'static/profiles/62454045_2336915723241848_5582742548838875136_o_grid.jpg', 5, '2021-09-25 16:41:34.213240');

-- --------------------------------------------------------

--
-- Table structure for table `auth_group`
--

CREATE TABLE `auth_group` (
  `id` int(11) NOT NULL,
  `name` varchar(150) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

--
-- Table structure for table `auth_group_permissions`
--

CREATE TABLE `auth_group_permissions` (
  `id` bigint(20) NOT NULL,
  `group_id` int(11) NOT NULL,
  `permission_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

--
-- Table structure for table `auth_permission`
--

CREATE TABLE `auth_permission` (
  `id` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `content_type_id` int(11) NOT NULL,
  `codename` varchar(100) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `auth_permission`
--

INSERT INTO `auth_permission` (`id`, `name`, `content_type_id`, `codename`) VALUES
(1, 'Can add log entry', 1, 'add_logentry'),
(2, 'Can change log entry', 1, 'change_logentry'),
(3, 'Can delete log entry', 1, 'delete_logentry'),
(4, 'Can view log entry', 1, 'view_logentry'),
(5, 'Can add permission', 2, 'add_permission'),
(6, 'Can change permission', 2, 'change_permission'),
(7, 'Can delete permission', 2, 'delete_permission'),
(8, 'Can view permission', 2, 'view_permission'),
(9, 'Can add group', 3, 'add_group'),
(10, 'Can change group', 3, 'change_group'),
(11, 'Can delete group', 3, 'delete_group'),
(12, 'Can view group', 3, 'view_group'),
(13, 'Can add user', 4, 'add_user'),
(14, 'Can change user', 4, 'change_user'),
(15, 'Can delete user', 4, 'delete_user'),
(16, 'Can view user', 4, 'view_user'),
(17, 'Can add content type', 5, 'add_contenttype'),
(18, 'Can change content type', 5, 'change_contenttype'),
(19, 'Can delete content type', 5, 'delete_contenttype'),
(20, 'Can view content type', 5, 'view_contenttype'),
(21, 'Can add session', 6, 'add_session'),
(22, 'Can change session', 6, 'change_session'),
(23, 'Can delete session', 6, 'delete_session'),
(24, 'Can view session', 6, 'view_session'),
(25, 'Can add profile', 7, 'add_profile'),
(26, 'Can change profile', 7, 'change_profile'),
(27, 'Can delete profile', 7, 'delete_profile'),
(28, 'Can view profile', 7, 'view_profile'),
(29, 'Can add commission', 8, 'add_commission'),
(30, 'Can change commission', 8, 'change_commission'),
(31, 'Can delete commission', 8, 'delete_commission'),
(32, 'Can view commission', 8, 'view_commission'),
(33, 'Can add feedback', 9, 'add_feedback'),
(34, 'Can change feedback', 9, 'change_feedback'),
(35, 'Can delete feedback', 9, 'delete_feedback'),
(36, 'Can view feedback', 9, 'view_feedback'),
(37, 'Can add product', 10, 'add_product'),
(38, 'Can change product', 10, 'change_product'),
(39, 'Can delete product', 10, 'delete_product'),
(40, 'Can view product', 10, 'view_product'),
(41, 'Can add order', 11, 'add_order'),
(42, 'Can change order', 11, 'change_order'),
(43, 'Can delete order', 11, 'delete_order'),
(44, 'Can view order', 11, 'view_order'),
(45, 'Can add order item', 12, 'add_orderitem'),
(46, 'Can change order item', 12, 'change_orderitem'),
(47, 'Can delete order item', 12, 'delete_orderitem'),
(48, 'Can view order item', 12, 'view_orderitem'),
(49, 'Can add shipping address', 13, 'add_shippingaddress'),
(50, 'Can change shipping address', 13, 'change_shippingaddress'),
(51, 'Can delete shipping address', 13, 'delete_shippingaddress'),
(52, 'Can view shipping address', 13, 'view_shippingaddress'),
(53, 'Can add gallery', 14, 'add_gallery'),
(54, 'Can change gallery', 14, 'change_gallery'),
(55, 'Can delete gallery', 14, 'delete_gallery'),
(56, 'Can view gallery', 14, 'view_gallery');

-- --------------------------------------------------------

--
-- Table structure for table `auth_user`
--

CREATE TABLE `auth_user` (
  `id` int(11) NOT NULL,
  `password` varchar(128) NOT NULL,
  `last_login` datetime(6) DEFAULT NULL,
  `is_superuser` tinyint(1) NOT NULL,
  `username` varchar(150) NOT NULL,
  `first_name` varchar(150) NOT NULL,
  `last_name` varchar(150) NOT NULL,
  `email` varchar(254) NOT NULL,
  `is_staff` tinyint(1) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `date_joined` datetime(6) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `auth_user`
--

INSERT INTO `auth_user` (`id`, `password`, `last_login`, `is_superuser`, `username`, `first_name`, `last_name`, `email`, `is_staff`, `is_active`, `date_joined`) VALUES
(1, 'pbkdf2_sha256$260000$68l10wtyjhfcE4aA2cm9IT$iM7TcCU3YHnAc17bdSQc2g3YRAVtziV2qmVhuEi52rU=', '2021-09-28 10:49:11.664874', 1, 'Sana', '', '', 'sana@gmail.com', 1, 1, '2021-09-21 08:06:13.348442'),
(2, 'pbkdf2_sha256$260000$x0B4jmt0l781KSCygIzfEu$sk2jsUoeo0fJqLdtI+vvmyuCjO/KFc7qMDP5NjvYxJ8=', '2021-09-28 11:09:16.407165', 0, 'Ruby', '', '', 'manisha.basukala012@gmail.com', 0, 1, '2021-09-21 08:13:57.846077'),
(3, '!FZFgAm7Or77aincnUkp8vUvIgWMmAxbL1vBw3D2T', NULL, 0, 'MAnny', '', '', 'manisha.basukala012@gmail.com', 1, 1, '2021-09-21 17:42:16.124175'),
(4, 'pbkdf2_sha256$260000$xeg2q0eFqVeSEUmggsIeAF$Lj56X87yNes7dz9i6dVowwwH+W5cSWURXdfYQc27zBM=', NULL, 0, 'admin', '', '', 'manisha.basukala012@gmail.com', 0, 1, '2021-09-21 17:43:11.874637'),
(5, 'pbkdf2_sha256$260000$7cBz1Qg1VxVppbF7nmBJwz$eOBiVZSHZbFNVz8OPUJRYaWnyrYoQBNzh4C56vALeFw=', '2021-09-28 05:55:18.821167', 0, 'Richa', '', '', 'basukala012@gmail.com', 1, 1, '2021-09-25 16:41:33.719221');

-- --------------------------------------------------------

--
-- Table structure for table `auth_user_groups`
--

CREATE TABLE `auth_user_groups` (
  `id` bigint(20) NOT NULL,
  `user_id` int(11) NOT NULL,
  `group_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

--
-- Table structure for table `auth_user_user_permissions`
--

CREATE TABLE `auth_user_user_permissions` (
  `id` bigint(20) NOT NULL,
  `user_id` int(11) NOT NULL,
  `permission_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

--
-- Table structure for table `django_admin_log`
--

CREATE TABLE `django_admin_log` (
  `id` int(11) NOT NULL,
  `action_time` datetime(6) NOT NULL,
  `object_id` longtext DEFAULT NULL,
  `object_repr` varchar(200) NOT NULL,
  `action_flag` smallint(5) UNSIGNED NOT NULL CHECK (`action_flag` >= 0),
  `change_message` longtext NOT NULL,
  `content_type_id` int(11) DEFAULT NULL,
  `user_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

--
-- Table structure for table `django_content_type`
--

CREATE TABLE `django_content_type` (
  `id` int(11) NOT NULL,
  `app_label` varchar(100) NOT NULL,
  `model` varchar(100) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `django_content_type`
--

INSERT INTO `django_content_type` (`id`, `app_label`, `model`) VALUES
(7, 'accounts', 'profile'),
(1, 'admin', 'logentry'),
(3, 'auth', 'group'),
(2, 'auth', 'permission'),
(4, 'auth', 'user'),
(5, 'contenttypes', 'contenttype'),
(8, 'mandala_circle', 'commission'),
(9, 'mandala_circle', 'feedback'),
(14, 'mandala_circle', 'gallery'),
(11, 'mandala_circle', 'order'),
(12, 'mandala_circle', 'orderitem'),
(10, 'mandala_circle', 'product'),
(13, 'mandala_circle', 'shippingaddress'),
(6, 'sessions', 'session');

-- --------------------------------------------------------

--
-- Table structure for table `django_migrations`
--

CREATE TABLE `django_migrations` (
  `id` bigint(20) NOT NULL,
  `app` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  `applied` datetime(6) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `django_migrations`
--

INSERT INTO `django_migrations` (`id`, `app`, `name`, `applied`) VALUES
(1, 'contenttypes', '0001_initial', '2021-09-21 08:04:18.786250'),
(2, 'auth', '0001_initial', '2021-09-21 08:04:24.975040'),
(3, 'accounts', '0001_initial', '2021-09-21 08:04:25.176115'),
(4, 'accounts', '0002_register', '2021-09-21 08:04:26.171852'),
(5, 'accounts', '0003_auto_20210831_2239', '2021-09-21 08:04:26.464154'),
(6, 'accounts', '0004_login_register', '2021-09-21 08:04:26.815189'),
(7, 'accounts', '0005_auto_20210905_2028', '2021-09-21 08:04:27.077774'),
(8, 'accounts', '0006_profile', '2021-09-21 08:04:28.027566'),
(9, 'accounts', '0007_auto_20210911_1913', '2021-09-21 08:04:29.657171'),
(10, 'accounts', '0008_profile_created_date', '2021-09-21 08:04:29.869871'),
(11, 'admin', '0001_initial', '2021-09-21 08:04:31.910757'),
(12, 'admin', '0002_logentry_remove_auto_add', '2021-09-21 08:04:31.978700'),
(13, 'admin', '0003_logentry_add_action_flag_choices', '2021-09-21 08:04:32.032160'),
(14, 'admins', '0001_initial', '2021-09-21 08:04:32.349520'),
(15, 'admins', '0002_auto_20210909_2330', '2021-09-21 08:04:32.445253'),
(16, 'admins', '0003_auto_20210910_1350', '2021-09-21 08:04:32.692848'),
(17, 'contenttypes', '0002_remove_content_type_name', '2021-09-21 08:04:33.155879'),
(18, 'auth', '0002_alter_permission_name_max_length', '2021-09-21 08:04:33.720872'),
(19, 'auth', '0003_alter_user_email_max_length', '2021-09-21 08:04:33.840424'),
(20, 'auth', '0004_alter_user_username_opts', '2021-09-21 08:04:33.887459'),
(21, 'auth', '0005_alter_user_last_login_null', '2021-09-21 08:04:34.257418'),
(22, 'auth', '0006_require_contenttypes_0002', '2021-09-21 08:04:34.297680'),
(23, 'auth', '0007_alter_validators_add_error_messages', '2021-09-21 08:04:34.358229'),
(24, 'auth', '0008_alter_user_username_max_length', '2021-09-21 08:04:34.472648'),
(25, 'auth', '0009_alter_user_last_name_max_length', '2021-09-21 08:04:34.585829'),
(26, 'auth', '0010_alter_group_name_max_length', '2021-09-21 08:04:34.713484'),
(27, 'auth', '0011_update_proxy_permissions', '2021-09-21 08:04:34.780429'),
(28, 'auth', '0012_alter_user_first_name_max_length', '2021-09-21 08:04:35.175183'),
(29, 'mandala_circle', '0001_initial', '2021-09-21 08:04:35.391742'),
(30, 'mandala_circle', '0002_alter_contact_email', '2021-09-21 08:04:35.416553'),
(31, 'mandala_circle', '0003_auto_20210909_1430', '2021-09-21 08:04:35.715130'),
(32, 'mandala_circle', '0004_alter_commission_message', '2021-09-21 08:04:36.208683'),
(33, 'mandala_circle', '0005_commissionreq', '2021-09-21 08:04:36.456018'),
(34, 'mandala_circle', '0006_auto_20210909_2330', '2021-09-21 08:04:36.769362'),
(35, 'mandala_circle', '0007_original_print', '2021-09-21 08:04:37.145968'),
(36, 'mandala_circle', '0008_auto_20210911_1528', '2021-09-21 08:04:37.238476'),
(37, 'mandala_circle', '0009_profile', '2021-09-21 08:04:38.094062'),
(38, 'mandala_circle', '0010_delete_profile', '2021-09-21 08:04:38.235968'),
(39, 'mandala_circle', '0011_auto_20210912_1256', '2021-09-21 08:04:38.820329'),
(40, 'mandala_circle', '0012_customer_order_orderitem_shippingaddress', '2021-09-21 08:04:43.567757'),
(41, 'mandala_circle', '0013_rename_original_product_product', '2021-09-21 08:04:44.395838'),
(42, 'mandala_circle', '0014_auto_20210913_1437', '2021-09-21 08:04:47.853458'),
(43, 'mandala_circle', '0015_auto_20210913_1559', '2021-09-21 08:04:51.745299'),
(44, 'mandala_circle', '0016_auto_20210913_1841', '2021-09-21 08:04:53.895506'),
(45, 'mandala_circle', '0017_cart_cartproduct_order', '2021-09-21 08:04:57.648823'),
(46, 'mandala_circle', '0018_auto_20210913_2027', '2021-09-21 08:04:59.333251'),
(47, 'mandala_circle', '0019_cart_orderplaced', '2021-09-21 08:05:02.054261'),
(48, 'mandala_circle', '0020_alter_cart_product', '2021-09-21 08:05:03.236745'),
(49, 'mandala_circle', '0021_alter_cart_product', '2021-09-21 08:05:05.056476'),
(50, 'mandala_circle', '0022_delete_orderplaced', '2021-09-21 08:05:05.212525'),
(51, 'mandala_circle', '0023_orderplaced', '2021-09-21 08:05:06.802566'),
(52, 'mandala_circle', '0024_rename_orderplaced_order', '2021-09-21 08:05:07.020843'),
(53, 'mandala_circle', '0025_delete_order', '2021-09-21 08:05:07.189000'),
(54, 'mandala_circle', '0026_orderplaced', '2021-09-21 08:05:08.946574'),
(55, 'mandala_circle', '0027_remove_orderplaced_payment_method', '2021-09-21 08:05:09.170103'),
(56, 'mandala_circle', '0028_auto_20210915_0334', '2021-09-21 08:05:13.251691'),
(57, 'mandala_circle', '0029_orderitem_status', '2021-09-21 08:05:13.749124'),
(58, 'mandala_circle', '0030_auto_20210917_2150', '2021-09-21 08:05:14.117506'),
(59, 'mandala_circle', '0031_shippingaddress_status', '2021-09-21 08:05:14.279248'),
(60, 'mandala_circle', '0032_remove_shippingaddress_status', '2021-09-21 08:05:14.488543'),
(61, 'mandala_circle', '0033_auto_20210918_1717', '2021-09-21 08:05:17.215567'),
(62, 'mandala_circle', '0034_auto_20210918_1723', '2021-09-21 08:05:19.097352'),
(63, 'mandala_circle', '0035_auto_20210918_1724', '2021-09-21 08:05:19.867017'),
(64, 'mandala_circle', '0036_alter_shippingaddress_quantity', '2021-09-21 08:05:21.288990'),
(65, 'mandala_circle', '0037_remove_shippingaddress_quantity', '2021-09-21 08:05:21.914607'),
(66, 'mandala_circle', '0038_auto_20210918_1749', '2021-09-21 08:05:23.046922'),
(67, 'mandala_circle', '0039_orderdetail_shippingaddress', '2021-09-21 08:05:25.903345'),
(68, 'mandala_circle', '0040_auto_20210920_2248', '2021-09-21 08:05:26.414942'),
(69, 'mandala_circle', '0041_auto_20210920_2259', '2021-09-21 08:05:26.614475'),
(70, 'mandala_circle', '0042_alter_order_user', '2021-09-21 08:05:27.901806'),
(71, 'mandala_circle', '0043_remove_order_payment', '2021-09-21 08:05:28.016761'),
(72, 'mandala_circle', '0044_orderitem_status', '2021-09-21 08:05:28.234951'),
(73, 'mandala_circle', '0045_auto_20210921_0008', '2021-09-21 08:05:28.519098'),
(74, 'mandala_circle', '0046_alter_order_status', '2021-09-21 08:05:28.567875'),
(75, 'mandala_circle', '0047_auto_20210921_0017', '2021-09-21 08:05:28.901028'),
(76, 'mandala_circle', '0048_alter_orderitem_status', '2021-09-21 08:05:30.023274'),
(77, 'mandala_circle', '0049_alter_orderitem_status', '2021-09-21 08:05:31.451078'),
(78, 'mandala_circle', '0050_alter_orderitem_status', '2021-09-21 08:05:31.495733'),
(79, 'mandala_circle', '0051_alter_orderitem_status', '2021-09-21 08:05:31.608574'),
(80, 'mandala_circle', '0052_alter_orderitem_status', '2021-09-21 08:05:31.694808'),
(81, 'mandala_circle', '0053_alter_orderitem_status', '2021-09-21 08:05:32.846418'),
(82, 'mandala_circle', '0054_alter_orderitem_status', '2021-09-21 08:05:33.898101'),
(83, 'mandala_circle', '0055_alter_orderitem_status', '2021-09-21 08:05:33.941736'),
(84, 'mandala_circle', '0056_alter_orderitem_status', '2021-09-21 08:05:35.240295'),
(85, 'mandala_circle', '0057_auto_20210921_1321', '2021-09-21 08:05:35.460154'),
(86, 'sessions', '0001_initial', '2021-09-21 08:05:36.018009'),
(87, 'mandala_circle', '0058_orderitem_delivered_status', '2021-09-25 08:00:08.212060'),
(88, 'mandala_circle', '0059_alter_orderitem_order_status', '2021-09-25 08:41:50.492543'),
(89, 'mandala_circle', '0060_shippingaddress_product', '2021-09-28 07:12:58.039496'),
(90, 'mandala_circle', '0061_remove_shippingaddress_product', '2021-09-28 07:28:50.121257'),
(91, 'mandala_circle', '0062_gallery', '2021-09-28 08:45:46.446258');

-- --------------------------------------------------------

--
-- Table structure for table `django_session`
--

CREATE TABLE `django_session` (
  `session_key` varchar(40) NOT NULL,
  `session_data` longtext NOT NULL,
  `expire_date` datetime(6) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `django_session`
--

INSERT INTO `django_session` (`session_key`, `session_data`, `expire_date`) VALUES
('4e7aw1kfvb7nzmran9me9ggq2njx341g', '.eJxVjDsOwjAQBe_iGln-Lg4lfc5g7XptHECOFCcV4u4QKQW0b2beS0Tc1hq3npc4sbgILU6_G2F65LYDvmO7zTLNbV0mkrsiD9rlOHN-Xg_376Bir98awDhmZx0NBOAMOW2yt5o9q0zqDEpbnUrmoFRBA4XZBzsEYCRWOoj3B8q3N5A:1mU8OY:SicTDTgrQVgjDXFQCPF17STyGscqtG4qbmNubtPUcZs', '2021-10-09 14:11:14.977261'),
('5rkp5j23a2ulj9d6c5wckpcrzhhl0t2d', '.eJxVjMsOwiAQRf-FtSE8pgy6dN9vIAMDUjU0Ke3K-O_apAvd3nPOfYlA21rD1vMSJhYXYcTpd4uUHrntgO_UbrNMc1uXKcpdkQftcpw5P6-H-3dQqddvXRwYcJCItdURDaBKFqCgH1IBPFtNBZUhhYw8FGSri88Oskfrsmfx_gDGNzdW:1mSjqE:5TLybl9cfNHHizshfy0SGk6vC-G7bTGrerI4rogr5hg', '2021-10-05 17:46:02.980001'),
('9rjobnw2u87i78yb6a39uo7pp0r091j6', '.eJxVjDsOwjAQBe_iGln-Lg4lfc5g7XptHECOFCcV4u4QKQW0b2beS0Tc1hq3npc4sbgILU6_G2F65LYDvmO7zTLNbV0mkrsiD9rlOHN-Xg_376Bir98awDhmZx0NBOAMOW2yt5o9q0zqDEpbnUrmoFRBA4XZBzsEYCRWOoj3B8q3N5A:1mUAIz:_kxgnfX5Sjws-5CwiX8G_FnzMbiHNOpO8cAfNcMIdTA', '2021-10-09 16:13:37.555870'),
('b35vwzkbxh4spqjsk4onbdfg466f0evv', '.eJxVjDsOwjAQBe_iGlnZXYy9lPScwVp_ggPIluKkQtwdIqWA9s3Meykv61L82vPsp6TOyqjD7xYkPnLdQLpLvTUdW13mKehN0Tvt-tpSfl529--gSC_fOmQmC46B4zFYcmAHIeJTMnFEdjKiOGJCizAYw4YxQQQn2RkQtEm9P7dNNpg:1mUBFT:wq8KZ3tm_cWnyOfzouQo4RY8ulfX9i8t5NgLfdvjPiY', '2021-10-09 17:14:03.549820'),
('jfmje9rpmrpkup2n3aztfwkpsfm3xloo', '.eJxVjMsOwiAQRf-FtSE8pgy6dN9vIAMDUjU0Ke3K-O_apAvd3nPOfYlA21rD1vMSJhYXYcTpd4uUHrntgO_UbrNMc1uXKcpdkQftcpw5P6-H-3dQqddvXRwYcJCItdURDaBKFqCgH1IBPFtNBZUhhYw8FGSri88Oskfrsmfx_gDGNzdW:1mVAz6:IDyNar_4YiDMZ8crxjDmxuLqMYrEeLcNLhyYGqKAJ6A', '2021-10-12 11:09:16.492788'),
('kyg63drf2xvidxognlxxfczdu2lx5fof', '.eJxVjMsOwiAQRf-FtSE8pgy6dN9vIAMDUjU0Ke3K-O_apAvd3nPOfYlA21rD1vMSJhYXYcTpd4uUHrntgO_UbrNMc1uXKcpdkQftcpw5P6-H-3dQqddvXRwYcJCItdURDaBKFqCgH1IBPFtNBZUhhYw8FGSri88Oskfrsmfx_gDGNzdW:1mV7dk:RlH09JV_HlE16PXTYaeXMuKGK6IQEt5lViO_vE42pRI', '2021-10-12 07:35:00.449794'),
('rtpewp07u5sd1iowu0nvmuefbpiacj3i', '.eJxVjDsOwjAQBe_iGln-Lg4lfc5g7XptHECOFCcV4u4QKQW0b2beS0Tc1hq3npc4sbgILU6_G2F65LYDvmO7zTLNbV0mkrsiD9rlOHN-Xg_376Bir98awDhmZx0NBOAMOW2yt5o9q0zqDEpbnUrmoFRBA4XZBzsEYCRWOoj3B8q3N5A:1mU9PW:58M13shPq4mWISQRaCOIZAOc4VyRsRWG1gTlFE2E2CM', '2021-10-09 15:16:18.248515'),
('yxipcfmxg0ui8b1l6ge6rc4eslp62ppd', '.eJxVjDsOwjAQBe_iGln-Lg4lfc5g7XptHECOFCcV4u4QKQW0b2beS0Tc1hq3npc4sbgILU6_G2F65LYDvmO7zTLNbV0mkrsiD9rlOHN-Xg_376Bir98awDhmZx0NBOAMOW2yt5o9q0zqDEpbnUrmoFRBA4XZBzsEYCRWOoj3B8q3N5A:1mU3Th:O2m9fUc30D2CfVO55GZJ7fsNSRgW_Fy8W6p2WHE2p24', '2021-10-09 08:56:13.342040'),
('zhxqs422ae3mg0kohck37gqamcr8ti5v', '.eJxVjMsOwiAQRf-FtSE8pgy6dN9vIAMDUjU0Ke3K-O_apAvd3nPOfYlA21rD1vMSJhYXYcTpd4uUHrntgO_UbrNMc1uXKcpdkQftcpw5P6-H-3dQqddvXRwYcJCItdURDaBKFqCgH1IBPFtNBZUhhYw8FGSri88Oskfrsmfx_gDGNzdW:1mSk8H:iYu2TSydpvQ9jgHLZksVO00Ai2zQv82BNvvw5hBCc6c', '2021-10-05 18:04:41.041942');

-- --------------------------------------------------------

--
-- Table structure for table `mandala_circle_commission`
--

CREATE TABLE `mandala_circle_commission` (
  `id` bigint(20) NOT NULL,
  `name` varchar(100) NOT NULL,
  `email` varchar(254) NOT NULL,
  `subject` varchar(100) NOT NULL,
  `message` longtext NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `mandala_circle_commission`
--

INSERT INTO `mandala_circle_commission` (`id`, `name`, `email`, `subject`, `message`) VALUES
(1, 'Manisha Basukala', 'manisha.basukala012@gmail.com', 'commission', 'I want to order commission art with my own design.\r\nI hope you will reply my faster.');

-- --------------------------------------------------------

--
-- Table structure for table `mandala_circle_feedback`
--

CREATE TABLE `mandala_circle_feedback` (
  `id` bigint(20) NOT NULL,
  `name` varchar(100) NOT NULL,
  `product_feedback` longtext NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `mandala_circle_feedback`
--

INSERT INTO `mandala_circle_feedback` (`id`, `name`, `product_feedback`) VALUES
(1, 'Manisha Basukala', 'Great work on your latest report. Your monthly goal was surpassed by over 50%! Your hard work will be a significant contribution'),
(2, 'Apple', 'I love your Art . Thank you so much for your service');

-- --------------------------------------------------------

--
-- Table structure for table `mandala_circle_gallery`
--

CREATE TABLE `mandala_circle_gallery` (
  `id` bigint(20) NOT NULL,
  `name` varchar(500) DEFAULT NULL,
  `image` varchar(100) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `mandala_circle_gallery`
--

INSERT INTO `mandala_circle_gallery` (`id`, `name`, `image`) VALUES
(4, 'Yellow magic', 'static/gallery/g1.jpg'),
(5, 'Lotus', 'static/gallery/g3.jpg'),
(6, 'Blue dot work', 'static/gallery/g5.jpg'),
(7, 'Lotus Buddha', 'static/gallery/g6.jpg'),
(8, 'Sky galaxy', 'static/gallery/g9.jpg'),
(9, 'Dark galaxy', 'static/gallery/g8.jpg'),
(10, 'Black magic', 'static/gallery/p4.jpg'),
(11, 'Green Magic Mandala', 'static/gallery/p1.jpg'),
(12, 'Blue mimosa', 'static/gallery/p3.jpg'),
(13, 'Starlight', 'static/gallery/o1.webp'),
(14, 'Flower of life', 'static/gallery/mandala1.webp'),
(15, 'Flower of life-2', 'static/gallery/p2.jpg'),
(16, 'Infinity', 'static/gallery/print1.webp'),
(17, 'Happiness', 'static/gallery/print2.jpg');

-- --------------------------------------------------------

--
-- Table structure for table `mandala_circle_order`
--

CREATE TABLE `mandala_circle_order` (
  `id` bigint(20) NOT NULL,
  `date_ordered` datetime(6) NOT NULL,
  `transaction_id` varchar(100) DEFAULT NULL,
  `user` varchar(2000) DEFAULT NULL,
  `complete` tinyint(1) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `mandala_circle_order`
--

INSERT INTO `mandala_circle_order` (`id`, `date_ordered`, `transaction_id`, `user`, `complete`) VALUES
(9, '2021-09-28 06:29:41.079002', '1632813528.121098', 'Ruby', 1),
(11, '2021-09-28 07:23:43.349291', '1632825665.611217', 'Ruby', 1),
(12, '2021-09-28 10:41:07.416568', NULL, 'Ruby', 0);

-- --------------------------------------------------------

--
-- Table structure for table `mandala_circle_orderitem`
--

CREATE TABLE `mandala_circle_orderitem` (
  `id` bigint(20) NOT NULL,
  `quantity` int(11) DEFAULT NULL,
  `date_added` datetime(6) NOT NULL,
  `order_id` bigint(20) DEFAULT NULL,
  `product_id` bigint(20) DEFAULT NULL,
  `order_status` varchar(50) NOT NULL,
  `delivered_status` tinyint(1) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `mandala_circle_orderitem`
--

INSERT INTO `mandala_circle_orderitem` (`id`, `quantity`, `date_added`, `order_id`, `product_id`, `order_status`, `delivered_status`) VALUES
(13, 1, '2021-09-28 07:15:37.613921', 9, 20, '', 1),
(15, 1, '2021-09-28 08:19:14.885874', 11, 12, '', 0),
(16, 1, '2021-09-28 10:42:44.982262', 12, 14, '', 0);

-- --------------------------------------------------------

--
-- Table structure for table `mandala_circle_product`
--

CREATE TABLE `mandala_circle_product` (
  `id` bigint(20) NOT NULL,
  `product_name` varchar(500) DEFAULT NULL,
  `product_price` double NOT NULL,
  `product_description` longtext DEFAULT NULL,
  `product_image` varchar(100) NOT NULL,
  `created_date` datetime(6) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `mandala_circle_product`
--

INSERT INTO `mandala_circle_product` (`id`, `product_name`, `product_price`, `product_description`, `product_image`, `created_date`) VALUES
(11, 'Mandala no 1-\"Flower of Life\"', 231, '- Original Artwork\r\n\r\n- Acrylics, inks, and gilding liquid on a wooden panel\r\n\r\n- Hangable\r\n\r\n- Size: 40cm x 40cm x 3.1cm/15.7\" x 15.7\" x 1.2\"', 'static/uploads/mandala1.webp', '2021-09-25 16:17:32.450475'),
(12, 'Mandala no 2-\"Green Magic Mandala\"', 300, '- Original Artwork\r\n\r\n- Acrylics, inks, and gilding liquid on a wooden panel\r\n\r\n- Hangable\r\n\r\n- Size: 40cm x 40cm x 3.1cm/15.7\" x 15.7\" x 1.2\"', 'static/uploads/p1.jpg', '2021-09-28 05:52:09.119297'),
(13, 'Mandala no 3-\"Blue Mimosa Mandala\"', 300, '- Original Artwork\r\n\r\n- Acrylics, inks, and gilding liquid on a wooden panel\r\n\r\n- Hangable\r\n\r\n- Size: 40cm x 40cm x 3.1cm/15.7\" x 15.7\" x 1.2\"', 'static/uploads/p3.jpg', '2021-09-28 05:52:22.150170'),
(14, 'Mandala no 4-\"Flower of life 2\"', 455, '- Original Artwork\r\n\r\n- Acrylics, inks, and gilding liquid on a wooden panel\r\n\r\n- Hangable\r\n\r\n- Size: 40cm x 40cm x 3.1cm/15.7\" x 15.7\" x 1.2\"', 'static/uploads/p2.jpg', '2021-09-28 05:52:44.422264'),
(15, 'Mandala no 5-\"Home\"', 325, '- Original Artwork\r\n\r\n- Acrylics, inks, and gilding liquid on a wooden panel\r\n\r\n- Hangable\r\n\r\n- Size: 40cm x 40cm x 3.1cm/15.7\" x 15.7\" x 1.2\"', 'static/uploads/o1.webp', '2021-09-28 05:53:01.555623'),
(16, 'Mandala no 6-\"Infinity\"', 900, '- Original Artwork\r\n\r\n- Acrylics, inks, and gilding liquid on a wooden panel\r\n\r\n- Hangable\r\n\r\n- Size: 40cm x 40cm x 3.1cm/15.7\" x 15.7\" x 1.2\"', 'static/uploads/print1.webp', '2021-09-28 05:53:21.708571'),
(17, 'Mandala no 7-\"Happiness\"', 500, '- Original Artwork\r\n\r\n- Acrylics, inks, and gilding liquid on a wooden panel\r\n\r\n- Hangable\r\n\r\n- Size: 40cm x 40cm x 3.1cm/15.7\" x 15.7\" x 1.2\"', 'static/uploads/print2.jpg', '2021-09-28 05:53:38.028073'),
(18, 'Mandala no 8-\"Black magic\"', 566, '- Original Artwork\r\n\r\n- Acrylics, inks, and gilding liquid on a wooden panel\r\n\r\n- Hangable\r\n\r\n- Size: 40cm x 40cm x 3.1cm/15.7\" x 15.7\" x 1.2\"', 'static/uploads/p4.jpg', '2021-09-28 05:53:53.295827'),
(19, 'Mandala no 9-Starlight', 700, '- Original Artwork\r\n\r\n- Acrylics, inks, and gilding liquid on a wooden panel\r\n\r\n- Hangable\r\n\r\n- Size: 40cm x 40cm x 3.1cm/15.7\" x 15.7\" x 1.2\"', 'static/uploads/print3.jpg', '2021-09-28 05:54:08.516295'),
(20, 'Mandala no 10-\"Beauty\"', 290, '- Original Artwork\r\n\r\n- Acrylics, inks, and gilding liquid on a wooden panel\r\n\r\n- Hangable\r\n\r\n- Size: 40cm x 40cm x 3.1cm/15.7\" x 15.7\" x 1.2\"', 'static/uploads/print6.jpg', '2021-09-28 05:54:38.398258');

-- --------------------------------------------------------

--
-- Table structure for table `mandala_circle_shippingaddress`
--

CREATE TABLE `mandala_circle_shippingaddress` (
  `id` bigint(20) NOT NULL,
  `address` varchar(200) NOT NULL,
  `city` varchar(200) NOT NULL,
  `state` varchar(200) NOT NULL,
  `zipcode` varchar(200) NOT NULL,
  `date_added` datetime(6) NOT NULL,
  `order_id` bigint(20) DEFAULT NULL,
  `user_id` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `mandala_circle_shippingaddress`
--

INSERT INTO `mandala_circle_shippingaddress` (`id`, `address`, `city`, `state`, `zipcode`, `date_added`, `order_id`, `user_id`) VALUES
(6, 'Byasi', 'Bhaktapur', 'Bagmati', '44800', '2021-09-28 07:18:48.468886', 9, 2),
(7, 'Kathmandu', 'Kathmandu', 'Bagmati', '46689', '2021-09-28 10:41:05.988149', 11, 2);

--
-- Indexes for dumped tables
--

--
-- Indexes for table `accounts_profile`
--
ALTER TABLE `accounts_profile`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `user_id` (`user_id`);

--
-- Indexes for table `auth_group`
--
ALTER TABLE `auth_group`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `name` (`name`);

--
-- Indexes for table `auth_group_permissions`
--
ALTER TABLE `auth_group_permissions`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `auth_group_permissions_group_id_permission_id_0cd325b0_uniq` (`group_id`,`permission_id`),
  ADD KEY `auth_group_permissio_permission_id_84c5c92e_fk_auth_perm` (`permission_id`);

--
-- Indexes for table `auth_permission`
--
ALTER TABLE `auth_permission`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `auth_permission_content_type_id_codename_01ab375a_uniq` (`content_type_id`,`codename`);

--
-- Indexes for table `auth_user`
--
ALTER TABLE `auth_user`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- Indexes for table `auth_user_groups`
--
ALTER TABLE `auth_user_groups`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `auth_user_groups_user_id_group_id_94350c0c_uniq` (`user_id`,`group_id`),
  ADD KEY `auth_user_groups_group_id_97559544_fk_auth_group_id` (`group_id`);

--
-- Indexes for table `auth_user_user_permissions`
--
ALTER TABLE `auth_user_user_permissions`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `auth_user_user_permissions_user_id_permission_id_14a6b632_uniq` (`user_id`,`permission_id`),
  ADD KEY `auth_user_user_permi_permission_id_1fbb5f2c_fk_auth_perm` (`permission_id`);

--
-- Indexes for table `django_admin_log`
--
ALTER TABLE `django_admin_log`
  ADD PRIMARY KEY (`id`),
  ADD KEY `django_admin_log_content_type_id_c4bce8eb_fk_django_co` (`content_type_id`),
  ADD KEY `django_admin_log_user_id_c564eba6_fk_auth_user_id` (`user_id`);

--
-- Indexes for table `django_content_type`
--
ALTER TABLE `django_content_type`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `django_content_type_app_label_model_76bd3d3b_uniq` (`app_label`,`model`);

--
-- Indexes for table `django_migrations`
--
ALTER TABLE `django_migrations`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `django_session`
--
ALTER TABLE `django_session`
  ADD PRIMARY KEY (`session_key`),
  ADD KEY `django_session_expire_date_a5c62663` (`expire_date`);

--
-- Indexes for table `mandala_circle_commission`
--
ALTER TABLE `mandala_circle_commission`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `mandala_circle_feedback`
--
ALTER TABLE `mandala_circle_feedback`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `mandala_circle_gallery`
--
ALTER TABLE `mandala_circle_gallery`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `mandala_circle_order`
--
ALTER TABLE `mandala_circle_order`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `mandala_circle_orderitem`
--
ALTER TABLE `mandala_circle_orderitem`
  ADD PRIMARY KEY (`id`),
  ADD KEY `mandala_circle_order_order_id_bf32746a_fk_mandala_c` (`order_id`),
  ADD KEY `mandala_circle_order_product_id_07ad8dbb_fk_mandala_c` (`product_id`);

--
-- Indexes for table `mandala_circle_product`
--
ALTER TABLE `mandala_circle_product`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `mandala_circle_shippingaddress`
--
ALTER TABLE `mandala_circle_shippingaddress`
  ADD PRIMARY KEY (`id`),
  ADD KEY `mandala_circle_shipp_order_id_a407b500_fk_mandala_c` (`order_id`),
  ADD KEY `mandala_circle_shippingaddress_user_id_d041b9a7_fk_auth_user_id` (`user_id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `accounts_profile`
--
ALTER TABLE `accounts_profile`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `auth_group`
--
ALTER TABLE `auth_group`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `auth_group_permissions`
--
ALTER TABLE `auth_group_permissions`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `auth_permission`
--
ALTER TABLE `auth_permission`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=57;

--
-- AUTO_INCREMENT for table `auth_user`
--
ALTER TABLE `auth_user`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT for table `auth_user_groups`
--
ALTER TABLE `auth_user_groups`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `auth_user_user_permissions`
--
ALTER TABLE `auth_user_user_permissions`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `django_admin_log`
--
ALTER TABLE `django_admin_log`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `django_content_type`
--
ALTER TABLE `django_content_type`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=15;

--
-- AUTO_INCREMENT for table `django_migrations`
--
ALTER TABLE `django_migrations`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=92;

--
-- AUTO_INCREMENT for table `mandala_circle_commission`
--
ALTER TABLE `mandala_circle_commission`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `mandala_circle_feedback`
--
ALTER TABLE `mandala_circle_feedback`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `mandala_circle_gallery`
--
ALTER TABLE `mandala_circle_gallery`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=18;

--
-- AUTO_INCREMENT for table `mandala_circle_order`
--
ALTER TABLE `mandala_circle_order`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=13;

--
-- AUTO_INCREMENT for table `mandala_circle_orderitem`
--
ALTER TABLE `mandala_circle_orderitem`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=17;

--
-- AUTO_INCREMENT for table `mandala_circle_product`
--
ALTER TABLE `mandala_circle_product`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=21;

--
-- AUTO_INCREMENT for table `mandala_circle_shippingaddress`
--
ALTER TABLE `mandala_circle_shippingaddress`
  MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=8;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `accounts_profile`
--
ALTER TABLE `accounts_profile`
  ADD CONSTRAINT `accounts_profile_user_id_49a85d32_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`);

--
-- Constraints for table `auth_group_permissions`
--
ALTER TABLE `auth_group_permissions`
  ADD CONSTRAINT `auth_group_permissio_permission_id_84c5c92e_fk_auth_perm` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`id`),
  ADD CONSTRAINT `auth_group_permissions_group_id_b120cbf9_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`);

--
-- Constraints for table `auth_permission`
--
ALTER TABLE `auth_permission`
  ADD CONSTRAINT `auth_permission_content_type_id_2f476e4b_fk_django_co` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`);

--
-- Constraints for table `auth_user_groups`
--
ALTER TABLE `auth_user_groups`
  ADD CONSTRAINT `auth_user_groups_group_id_97559544_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`),
  ADD CONSTRAINT `auth_user_groups_user_id_6a12ed8b_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`);

--
-- Constraints for table `auth_user_user_permissions`
--
ALTER TABLE `auth_user_user_permissions`
  ADD CONSTRAINT `auth_user_user_permi_permission_id_1fbb5f2c_fk_auth_perm` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`id`),
  ADD CONSTRAINT `auth_user_user_permissions_user_id_a95ead1b_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`);

--
-- Constraints for table `django_admin_log`
--
ALTER TABLE `django_admin_log`
  ADD CONSTRAINT `django_admin_log_content_type_id_c4bce8eb_fk_django_co` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`),
  ADD CONSTRAINT `django_admin_log_user_id_c564eba6_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`);

--
-- Constraints for table `mandala_circle_orderitem`
--
ALTER TABLE `mandala_circle_orderitem`
  ADD CONSTRAINT `mandala_circle_order_order_id_bf32746a_fk_mandala_c` FOREIGN KEY (`order_id`) REFERENCES `mandala_circle_order` (`id`),
  ADD CONSTRAINT `mandala_circle_order_product_id_07ad8dbb_fk_mandala_c` FOREIGN KEY (`product_id`) REFERENCES `mandala_circle_product` (`id`);

--
-- Constraints for table `mandala_circle_shippingaddress`
--
ALTER TABLE `mandala_circle_shippingaddress`
  ADD CONSTRAINT `mandala_circle_shipp_order_id_a407b500_fk_mandala_c` FOREIGN KEY (`order_id`) REFERENCES `mandala_circle_order` (`id`),
  ADD CONSTRAINT `mandala_circle_shippingaddress_user_id_d041b9a7_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
