USE [MysqlInventory]
GO

/****** Object:  Table [dbo].[My_ServerInventory]    Script Date: 4.11.2026 09:43:29 ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[My_ServerInventory](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[ServerName] [nvarchar](256) NULL,
	[OSVersion] [nvarchar](256) NULL,
	[LogicalCPU] [int] NULL,
	[CoresPerCPU] [int] NULL,
	[PhysicalCPU] [int] NULL,
	[Memory] [int] NULL,
	[ListeningIP] [nvarchar](64) NULL,
	[ListeningPort] [nvarchar](16) NULL,
	[Virtualization] [nvarchar](64) NULL,
	[DomainName] [nvarchar](256) NULL,
	[Fqdn] [nvarchar](256) NULL,
	[Type] [nvarchar](16) NULL,
	[is3rdParty] [bit] NULL,
	[CreateDate] [datetime] NULL,
	[LastUpdateDate] [datetime] NULL,
	[LastUpdateReason] [nvarchar](max) NULL,
	[DeleteDate] [datetime] NULL,
	[isActive] [bit] NULL,
	[isCollect] [bit] NULL,
	[ValidFrom] [datetime2](7) GENERATED ALWAYS AS ROW START NOT NULL,
	[ValidTo] [datetime2](7) GENERATED ALWAYS AS ROW END NOT NULL,
 CONSTRAINT [PK_My_ServerInventory] PRIMARY KEY CLUSTERED 
(
	[id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 90, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY],
	PERIOD FOR SYSTEM_TIME ([ValidFrom], [ValidTo])
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
WITH
(
SYSTEM_VERSIONING = ON (HISTORY_TABLE = [dbo].[My_ServerInventory_History])
)
GO


