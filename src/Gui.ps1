# =====================================================================================================================
#  WINDOW
#  WPF, declared in XAML and wired up with PowerShell script blocks. All long work runs in one background runspace
#  that holds the engine, so the window stays responsive and the derived keystream is reused between actions. The UI
#  thread polls a synchronized hashtable every 150 ms for progress, log lines and completion.
# =====================================================================================================================
$DqeXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Defender Quarantine Extractor" Width="1240" Height="860" MinWidth="640" MinHeight="420" WindowStartupLocation="CenterScreen"
        Background="#14171C" Foreground="#E6E9EE" FontFamily="Segoe UI" FontSize="13" AllowDrop="True" UseLayoutRounding="True" TextOptions.TextFormattingMode="Display">
  <Window.Resources>
    <SolidColorBrush x:Key="Bg" Color="#14171C"/><SolidColorBrush x:Key="Surface" Color="#1B1F26"/><SolidColorBrush x:Key="Field" Color="#10131A"/>
    <SolidColorBrush x:Key="Line" Color="#2C333E"/><SolidColorBrush x:Key="Ink" Color="#E6E9EE"/><SolidColorBrush x:Key="Muted" Color="#9AA3B2"/>
    <SolidColorBrush x:Key="Accent" Color="#E8A33D"/><SolidColorBrush x:Key="AccentInk" Color="#1A1305"/><SolidColorBrush x:Key="Hover" Color="#242A34"/>
    <SolidColorBrush x:Key="Sel" Color="#33290F"/><SolidColorBrush x:Key="Ok" Color="#74D39C"/><SolidColorBrush x:Key="Bad" Color="#FF8F86"/>
    <Style TargetType="TextBlock"><Setter Property="Foreground" Value="{StaticResource Ink}"/></Style>
    <Style x:Key="Label" TargetType="TextBlock"><Setter Property="Foreground" Value="{StaticResource Muted}"/><Setter Property="Margin" Value="0,8,0,3"/><Setter Property="FontSize" Value="12"/></Style>
    <Style x:Key="Cell" TargetType="TextBlock"><Setter Property="TextWrapping" Value="Wrap"/><Setter Property="Foreground" Value="{StaticResource Ink}"/></Style>
    <Style x:Key="Head" TargetType="TextBlock"><Setter Property="Foreground" Value="{StaticResource Ink}"/><Setter Property="FontSize" Value="14"/><Setter Property="FontWeight" Value="SemiBold"/></Style>
    <Style TargetType="TextBox">
      <Setter Property="Background" Value="{StaticResource Field}"/><Setter Property="Foreground" Value="{StaticResource Ink}"/><Setter Property="CaretBrush" Value="{StaticResource Ink}"/>
      <Setter Property="BorderBrush" Value="{StaticResource Line}"/><Setter Property="BorderThickness" Value="1"/><Setter Property="Padding" Value="7,4"/><Setter Property="MinHeight" Value="30"/><Setter Property="VerticalContentAlignment" Value="Center"/><Setter Property="SelectionBrush" Value="{StaticResource Accent}"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="TextBox">
        <Border x:Name="b" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1" CornerRadius="5"><ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}" VerticalAlignment="{TemplateBinding VerticalContentAlignment}"/></Border>
        <ControlTemplate.Triggers>
          <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="#46505F"/></Trigger>
          <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="{StaticResource Accent}"/></Trigger>
          <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.55"/></Trigger>
        </ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter>
    </Style>
    <Style TargetType="Button">
      <Setter Property="Background" Value="{StaticResource Surface}"/><Setter Property="Foreground" Value="{StaticResource Ink}"/><Setter Property="BorderBrush" Value="{StaticResource Line}"/>
      <Setter Property="Padding" Value="14,7"/><Setter Property="MinHeight" Value="32"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
        <Border x:Name="b" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1" CornerRadius="5">
          <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" Margin="{TemplateBinding Padding}" RecognizesAccessKey="True"/></Border>
        <ControlTemplate.Triggers>
          <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="{StaticResource Hover}"/><Setter TargetName="b" Property="BorderBrush" Value="#46505F"/></Trigger>
          <Trigger Property="IsPressed" Value="True"><Setter TargetName="b" Property="Background" Value="#10131A"/></Trigger>
          <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="{StaticResource Accent}"/></Trigger>
          <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.45"/><Setter Property="Cursor" Value="Arrow"/></Trigger>
        </ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter>
    </Style>
    <Style x:Key="Primary" TargetType="Button">
      <Setter Property="Background" Value="{StaticResource Accent}"/><Setter Property="Foreground" Value="{StaticResource AccentInk}"/><Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Padding" Value="20,8"/><Setter Property="MinHeight" Value="36"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
        <Border x:Name="b" Background="{TemplateBinding Background}" CornerRadius="5" BorderThickness="1" BorderBrush="{TemplateBinding Background}">
          <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" Margin="{TemplateBinding Padding}" RecognizesAccessKey="True"/></Border>
        <ControlTemplate.Triggers>
          <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#F2B458"/></Trigger>
          <Trigger Property="IsPressed" Value="True"><Setter TargetName="b" Property="Background" Value="#C98A2C"/></Trigger>
          <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="#FFFFFF"/></Trigger>
          <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.4"/><Setter Property="Cursor" Value="Arrow"/></Trigger>
        </ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter>
    </Style>
    <Style TargetType="CheckBox"><Setter Property="Foreground" Value="{StaticResource Ink}"/><Setter Property="Margin" Value="0,5,0,0"/><Setter Property="VerticalContentAlignment" Value="Center"/><Setter Property="Cursor" Value="Hand"/></Style>
    <Style TargetType="RadioButton"><Setter Property="Foreground" Value="{StaticResource Ink}"/><Setter Property="Margin" Value="0,6,0,0"/><Setter Property="VerticalContentAlignment" Value="Center"/><Setter Property="Cursor" Value="Hand"/></Style>
    <Style TargetType="ToolTip"><Setter Property="Background" Value="#242A34"/><Setter Property="Foreground" Value="#E6E9EE"/><Setter Property="BorderBrush" Value="#46505F"/><Setter Property="Padding" Value="8,5"/></Style>
    <Style TargetType="Thumb" x:Key="BarThumb"><Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Thumb"><Border CornerRadius="4" Background="#3A4350" Margin="2"/></ControlTemplate></Setter.Value></Setter></Style>
    <Style TargetType="ScrollBar">
      <Setter Property="Background" Value="Transparent"/><Setter Property="Width" Value="12"/><Setter Property="MinWidth" Value="12"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="ScrollBar">
        <Grid Background="Transparent"><Track x:Name="PART_Track" IsDirectionReversed="True"><Track.Thumb><Thumb Style="{StaticResource BarThumb}"/></Track.Thumb></Track></Grid>
      </ControlTemplate></Setter.Value></Setter>
      <Style.Triggers><Trigger Property="Orientation" Value="Horizontal">
        <Setter Property="Width" Value="Auto"/><Setter Property="MinWidth" Value="0"/><Setter Property="Height" Value="12"/><Setter Property="MinHeight" Value="12"/>
        <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="ScrollBar">
          <Grid Background="Transparent"><Track x:Name="PART_Track"><Track.Thumb><Thumb Style="{StaticResource BarThumb}"/></Track.Thumb></Track></Grid>
        </ControlTemplate></Setter.Value></Setter></Trigger></Style.Triggers>
    </Style>
    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="#171A20"/><Setter Property="Foreground" Value="{StaticResource Muted}"/><Setter Property="Padding" Value="10,8"/><Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="BorderBrush" Value="{StaticResource Line}"/><Setter Property="BorderThickness" Value="0,0,0,1"/><Setter Property="HorizontalContentAlignment" Value="Left"/>
      <Setter Property="ContentTemplate"><Setter.Value><DataTemplate><TextBlock Text="{Binding}" TextWrapping="Wrap"/></DataTemplate></Setter.Value></Setter>
    </Style>
    <Style TargetType="DataGridCell">
      <Setter Property="BorderThickness" Value="0"/><Setter Property="Foreground" Value="{StaticResource Ink}"/><Setter Property="FocusVisualStyle" Value="{x:Null}"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="DataGridCell"><Border Background="{TemplateBinding Background}" Padding="10,6"><ContentPresenter VerticalAlignment="Center"/></Border></ControlTemplate></Setter.Value></Setter>
      <Style.Triggers><Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{StaticResource Sel}"/><Setter Property="Foreground" Value="{StaticResource Ink}"/></Trigger></Style.Triggers>
    </Style>
    <Style TargetType="DataGridRow">
      <Setter Property="Background" Value="Transparent"/>
      <Style.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="{StaticResource Hover}"/></Trigger>
        <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{StaticResource Sel}"/></Trigger></Style.Triggers>
    </Style>
    <Style TargetType="ProgressBar">
      <Setter Property="Height" Value="6"/><Setter Property="Foreground" Value="{StaticResource Accent}"/><Setter Property="Background" Value="#242A34"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="ProgressBar">
        <Grid><Border x:Name="PART_Track" Background="{TemplateBinding Background}" CornerRadius="3"/>
          <Border x:Name="PART_Indicator" Background="{TemplateBinding Foreground}" CornerRadius="3" HorizontalAlignment="Left"/></Grid>
      </ControlTemplate></Setter.Value></Setter>
    </Style>
  </Window.Resources>
  <!-- On small or highly scaled screens the layout keeps a usable minimum size and scrolls instead of clipping. -->
  <ScrollViewer x:Name="RootScroll" HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Auto" Focusable="False">
  <Border Padding="20,16,20,16" MinWidth="780" MinHeight="520"
          Width="{Binding ViewportWidth, ElementName=RootScroll}" Height="{Binding ViewportHeight, ElementName=RootScroll}">
  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*" MinHeight="150"/><!-- list and options -->
      <RowDefinition Height="12"/><RowDefinition Height="0.22*" MinHeight="58" MaxHeight="420"/><!-- activity log --><RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <Grid Grid.Row="0" Margin="0,0,0,10">
      <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
      <Image x:Name="ImgEmblem" Width="34" Height="34" Margin="0,0,12,0" RenderOptions.BitmapScalingMode="HighQuality"/>
      <TextBlock Grid.Column="1" Text="Defender Quarantine Extractor" FontSize="18" FontWeight="SemiBold" VerticalAlignment="Center"/>
      <TextBlock x:Name="TxtVersion" Grid.Column="2" Foreground="{StaticResource Muted}" FontSize="12" VerticalAlignment="Center"/>
    </Grid>

    <Border Grid.Row="1" Background="{StaticResource Surface}" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="8" Padding="14,10" Margin="0,0,0,10">
      <Grid>
        <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
        <Grid.RowDefinitions><RowDefinition/><RowDefinition/><RowDefinition/></Grid.RowDefinitions>
        <TextBlock Text="Source" Style="{StaticResource Head}" VerticalAlignment="Center" Margin="0,0,14,0"/>
        <TextBox x:Name="TxtSource" Grid.Column="1" ToolTip="A collected .zip or .gz, an extracted folder at any level, or several separated by semicolons. You can also drop files or folders onto this window."/>
        <Button x:Name="BtnZip" Grid.Column="2" Content="Zip..." Margin="8,0,0,0" ToolTip="Choose one or more collected archives (.zip, .gz)."/>
        <Button x:Name="BtnFolder" Grid.Column="3" Content="Folder..." Margin="8,0,0,0" ToolTip="Choose an extracted collection, a Windows Defender folder, or a folder of loose Defender files."/>
        <Button x:Name="BtnLoad" Grid.Column="4" Grid.ColumnSpan="2" Content="Load" Margin="8,0,0,0" MinWidth="104" HorizontalAlignment="Right"/>
        <TextBlock Grid.Row="1" Text="Save to" Style="{StaticResource Head}" VerticalAlignment="Center" Margin="0,8,14,0"/>
        <TextBox x:Name="TxtOut" Grid.Row="1" Grid.Column="1" Margin="0,8,0,0" ToolTip="Folder for the encrypted archive and the report."/>
        <Button x:Name="BtnOut" Grid.Row="1" Grid.Column="2" Grid.ColumnSpan="2" Content="Choose folder..." Margin="8,8,0,0"/>
        <Grid Grid.Row="1" Grid.Column="4" Grid.ColumnSpan="2" Margin="8,8,0,0">
          <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
          <TextBlock Text="Zip password" Foreground="{StaticResource Muted}" FontSize="12" VerticalAlignment="Center" Margin="0,0,8,0"/>
          <TextBox x:Name="TxtSrcPw" Grid.Column="1" MinWidth="110" FontFamily="Consolas" ToolTip="Password of a protected input archive. Common sample passwords are tried automatically."/>
        </Grid>
        <TextBlock x:Name="TxtSummary" Grid.Row="2" Grid.Column="1" Grid.ColumnSpan="5" Foreground="{StaticResource Muted}" Margin="0,8,0,0" TextWrapping="Wrap"
                   Text="Select a collected archive or folder."/>
      </Grid>
    </Border>

    <Grid Grid.Row="2">
      <Grid.ColumnDefinitions><ColumnDefinition Width="*" MinWidth="360"/><ColumnDefinition Width="12"/><ColumnDefinition Width="300" MinWidth="240" MaxWidth="600"/></Grid.ColumnDefinitions>
      <GridSplitter Grid.Column="1" Width="12" HorizontalAlignment="Stretch" VerticalAlignment="Stretch" Background="Transparent" Cursor="SizeWE"
                    ResizeDirection="Columns" ResizeBehavior="PreviousAndNext" Focusable="False" ToolTip="Drag to resize"/>
      <Border Background="{StaticResource Surface}" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="8">
        <Grid>
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
          <Grid Margin="14,12,14,10">
            <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
            <TextBlock Text="Quarantined items" Style="{StaticResource Head}" VerticalAlignment="Center"/>
            <StackPanel Grid.Column="1" Orientation="Horizontal">
              <Button x:Name="BtnOne" Content="Save selected as zip..." Padding="10,4" MinHeight="26" Margin="0,0,12,0" IsEnabled="False"
                      ToolTip="Writes the selected item to its own archive, with the password and encryption set on the right. Also available by double-click or right-click."/>
              <Button x:Name="BtnAll" Content="Tick all" Padding="10,4" MinHeight="26"/>
              <Button x:Name="BtnNone" Content="Untick all" Padding="10,4" MinHeight="26" Margin="6,0,0,0"/>
            </StackPanel>
          </Grid>
          <DataGrid x:Name="Grid" Grid.Row="1" AutoGenerateColumns="False" CanUserAddRows="False" CanUserDeleteRows="False" HeadersVisibility="Column" SelectionMode="Single" SelectionUnit="FullRow"
                    Background="Transparent" RowBackground="Transparent" BorderThickness="0" GridLinesVisibility="Horizontal" HorizontalGridLinesBrush="#242A34"
                    RowHeaderWidth="0" IsReadOnly="False" CanUserResizeRows="False" CanUserResizeColumns="True" CanUserSortColumns="True" CanUserReorderColumns="True"
                    HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Auto" ScrollViewer.CanContentScroll="True" EnableRowVirtualization="True">
            <DataGrid.Columns>
              <DataGridTemplateColumn Header="Export" Width="Auto" MinWidth="80" CanUserResize="False" CanUserSort="False" CanUserReorder="False">
                <DataGridTemplateColumn.CellTemplate><DataTemplate>
                  <CheckBox IsChecked="{Binding Sel, Mode=TwoWay, UpdateSourceTrigger=PropertyChanged}" IsEnabled="{Binding CanExport}" HorizontalAlignment="Center" Margin="0"/>
                </DataTemplate></DataGridTemplateColumn.CellTemplate>
              </DataGridTemplateColumn>
              <DataGridTextColumn Header="Threat" Binding="{Binding Threat}" IsReadOnly="True" Width="1.4*" MinWidth="130">
                <DataGridTextColumn.ElementStyle><Style TargetType="TextBlock" BasedOn="{StaticResource Cell}"><Setter Property="ToolTip" Value="{Binding Threat}"/></Style></DataGridTextColumn.ElementStyle>
              </DataGridTextColumn>
              <DataGridTextColumn Header="Type" Binding="{Binding Type}" IsReadOnly="True" Width="0.8*" MinWidth="106" ElementStyle="{StaticResource Cell}"/>
              <DataGridTextColumn Header="Original path" Binding="{Binding Path}" IsReadOnly="True" Width="2.4*" MinWidth="104">
                <DataGridTextColumn.ElementStyle><Style TargetType="TextBlock" BasedOn="{StaticResource Cell}"><Setter Property="ToolTip" Value="{Binding Path}"/></Style></DataGridTextColumn.ElementStyle>
              </DataGridTextColumn>
              <DataGridTextColumn Header="Size" Binding="{Binding SizeText}" SortMemberPath="SizeNum" IsReadOnly="True" Width="Auto" MinWidth="64"/>
              <DataGridTextColumn Header="Stored payload" Binding="{Binding Payload}" IsReadOnly="True" Width="0.8*" MinWidth="76" ElementStyle="{StaticResource Cell}"/>
              <DataGridTextColumn Header="Quarantined (UTC)" Binding="{Binding Detected}" IsReadOnly="True" Width="0.9*" MinWidth="104" ElementStyle="{StaticResource Cell}"/>
            </DataGrid.Columns>
          </DataGrid>
          <TextBlock x:Name="TxtEmpty" Grid.Row="1" Text="Nothing loaded yet. Quarantined files, registry keys and services will be listed here." Foreground="{StaticResource Muted}"
                     HorizontalAlignment="Center" VerticalAlignment="Center" TextWrapping="Wrap" MaxWidth="420" TextAlignment="Center"/>
        </Grid>
      </Border>

      <Border Grid.Column="2" Background="{StaticResource Surface}" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="8">
        <ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel Margin="14,12,14,14">
          <TextBlock Text="Case" Style="{StaticResource Head}"/>
          <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="10"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
            <StackPanel><TextBlock Text="Case ID" Style="{StaticResource Label}"/><TextBox x:Name="TxtCase"/></StackPanel>
            <StackPanel Grid.Column="2"><TextBlock Text="Analyst" Style="{StaticResource Label}"/><TextBox x:Name="TxtAnalyst"/></StackPanel></Grid>
          <TextBlock Text="Title" Style="{StaticResource Label}"/><TextBox x:Name="TxtTitle"/>
          <TextBlock Text="Description" Style="{StaticResource Label}"/><TextBox x:Name="TxtDesc" AcceptsReturn="True" TextWrapping="Wrap" Height="52" VerticalScrollBarVisibility="Auto" VerticalContentAlignment="Top"/>

          <TextBlock Text="Archive" Style="{StaticResource Head}" Margin="0,16,0,0"/>
          <TextBlock Text="Password" Style="{StaticResource Label}"/><TextBox x:Name="TxtPassword" Text="infected" FontFamily="Consolas"/>
          <TextBlock Text="Encryption" Style="{StaticResource Label}"/>
          <RadioButton x:Name="RbAes" GroupName="enc" IsChecked="True" Content="AES-256" Margin="0"/>
          <RadioButton x:Name="RbZc" GroupName="enc" Content="ZipCrypto (legacy, slower)" Margin="0,4,0,0"/>
          <TextBlock Text="Original Defender artifacts to include" Style="{StaticResource Label}" Margin="0,10,0,4"/>
          <RadioButton x:Name="RbCore" GroupName="raw" IsChecked="True" Content="Files the tool analyses (recommended)" Margin="0" ToolTip="Quarantine store, detection and scan history, MPLog and MPDetection logs, event logs and history logs."/>
          <RadioButton x:Name="RbAll" GroupName="raw" Content="Everything in the source" Margin="0,4,0,0" ToolTip="Every file in the source, including logs, traces and support files the tool does not analyse."/>
          <RadioButton x:Name="RbNone" GroupName="raw" Content="None, recovered files and results only" Margin="0,4,0,0"/>
          <CheckBox x:Name="ChkPer" Content="Also write one archive per recovered file" Margin="0,12,0,0"/>
          <CheckBox x:Name="ChkVerify" Content="Verify the archive after writing" IsChecked="True"/>
          <CheckBox x:Name="ChkOpen" Content="Open the report when done" IsChecked="True"/>
        </StackPanel></ScrollViewer>
      </Border>
    </Grid>

    <GridSplitter Grid.Row="3" Height="12" HorizontalAlignment="Stretch" VerticalAlignment="Stretch" Background="Transparent" Cursor="SizeNS"
                  ResizeDirection="Rows" ResizeBehavior="PreviousAndNext" Focusable="False" ToolTip="Drag to resize the activity log"/>
    <Border Grid.Row="5" Margin="0,12,0,0">
      <Grid>
        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
        <StackPanel VerticalAlignment="Center" Margin="0,0,16,0">
          <TextBlock x:Name="TxtStage" Text="Ready." TextTrimming="CharacterEllipsis"/>
          <ProgressBar x:Name="Bar" Minimum="0" Maximum="100" Value="0" Margin="0,7,0,0"/>
        </StackPanel>
        <Button x:Name="BtnReport" Grid.Column="1" Content="Open report" Visibility="Collapsed" Margin="0,0,8,0"/>
        <Button x:Name="BtnShow" Grid.Column="2" Content="Show in folder" Visibility="Collapsed" Margin="0,0,8,0"/>
        <Button x:Name="BtnCancel" Grid.Column="3" Content="Cancel" Visibility="Collapsed" Margin="0,0,8,0"/>
        <Button x:Name="BtnGo" Grid.Column="4" Content="Generate package" Style="{StaticResource Primary}" IsEnabled="False"/>
      </Grid>
    </Border>

    <Border Grid.Row="4" Background="{StaticResource Field}" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="8">
      <TextBox x:Name="TxtLog" IsReadOnly="True" BorderThickness="0" Background="Transparent" FontFamily="Consolas" FontSize="12" Foreground="{StaticResource Muted}"
               VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled" TextWrapping="Wrap" VerticalContentAlignment="Top" Padding="10,8" Text="Activity log"/>
    </Border>
  </Grid>
  </Border>
  </ScrollViewer>
</Window>
'@

function New-DqeWindow {
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml, System.Data, System.Windows.Forms
    $win = [Windows.Markup.XamlReader]::Parse($DqeXaml)
    $ui = @{ Win = $win }
    foreach ($n in 'ImgEmblem', 'TxtVersion', 'TxtSource', 'BtnZip', 'BtnFolder', 'BtnLoad', 'TxtSrcPw', 'TxtSummary', 'Grid', 'TxtEmpty', 'BtnAll', 'BtnNone', 'BtnOne',
        'TxtCase', 'TxtAnalyst', 'TxtTitle', 'TxtDesc', 'TxtPassword', 'RbAes', 'RbZc', 'RbCore', 'RbAll', 'RbNone', 'ChkPer', 'ChkVerify', 'ChkOpen', 'TxtOut', 'BtnOut',
        'TxtStage', 'Bar', 'BtnReport', 'BtnShow', 'BtnCancel', 'BtnGo', 'TxtLog') { $ui[$n] = $win.FindName($n) }
    $script:DqeUi = $ui
    $script:DqeSync = [hashtable]::Synchronized(@{ Log = [Collections.ArrayList]::Synchronized((New-Object Collections.ArrayList)); State = 'idle'; Pct = 0.0; Stage = ''; Cancel = $false; Model = $null; Result = $null; Error = $null })
    $script:DqeState = @{ Ps = $null; Handle = $null; Mode = ''; LogPos = 0; Table = $null; Rs = $null; Last = $null; LogText = (New-Object Text.StringBuilder) }

    try {
        $bmp = New-Object Windows.Media.Imaging.BitmapImage; $bmp.BeginInit()
        $bmp.StreamSource = New-Object IO.MemoryStream (, [Convert]::FromBase64String($DqeEmblem)); $bmp.CacheOption = 'OnLoad'; $bmp.EndInit()
        $ui.ImgEmblem.Source = $bmp; $win.Icon = $bmp
    } catch { }
    $ui.TxtVersion.Text = 'Version __DQE_VERSION__'
    $ui.TxtAnalyst.Text = $env:USERNAME
    $ui.TxtLog.Text = ''
    try {
        # WorkArea is in device-independent units, so it already reflects display scaling (125 %, 150 %, ...).
        $wa = [Windows.SystemParameters]::WorkArea
        $win.Width = [Math]::Min(1280, $wa.Width - 24); $win.Height = [Math]::Min(880, $wa.Height - 24)
        if ($wa.Width -lt 1100 -or $wa.Height -lt 720) { $win.WindowState = 'Maximized' }
    } catch { }

    # one background runspace for the whole session, so derived keystream is reused between actions
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState = 'MTA'; $rs.ThreadOptions = 'ReuseThread'; $rs.Open()
    $init = [powershell]::Create(); $init.Runspace = $rs; [void]$init.AddScript($DqeEngine.ToString()); [void]$init.Invoke(); $init.Dispose()
    $script:DqeState.Rs = $rs

    $script:DqeSay = { param([string]$m) [void]$script:DqeSync.Log.Add(('{0}|info|{1}' -f (Get-Date).ToString('HH:mm:ss'), $m)) }
    $script:DqeBusy = {
        param([bool]$busy)
        $u = $script:DqeUi; $loaded = [bool]$script:DqeSync.Model
        foreach ($n in 'BtnZip', 'BtnFolder', 'BtnLoad', 'TxtSource', 'TxtSrcPw', 'BtnAll', 'BtnNone') { $u[$n].IsEnabled = -not $busy }
        $u.BtnGo.IsEnabled = (-not $busy) -and $loaded
        $u.BtnCancel.Visibility = if ($busy) { 'Visible' } else { 'Collapsed' }
        if ($busy) { $u.BtnReport.Visibility = 'Collapsed'; $u.BtnShow.Visibility = 'Collapsed'; $u.BtnOne.IsEnabled = $false } else { & $script:DqeRowChanged }
    }
    $script:DqeStart = {
        param([string]$mode, $a)
        if ($script:DqeSync.State -eq 'running') { return }
        $S = $script:DqeSync; $S.State = 'running'; $S.Pct = 0.0; $S.Stage = 'Starting'; $S.Cancel = $false; $S.Error = $null; $S.Result = $null
        $ps = [powershell]::Create(); $ps.Runspace = $script:DqeState.Rs
        [void]$ps.AddScript('Dqe-Job $args[0] $args[1] $args[2]').AddArgument($S).AddArgument($mode).AddArgument($a)
        $script:DqeState.Ps = $ps; $script:DqeState.Mode = $mode; $script:DqeState.Handle = $ps.BeginInvoke()
        & $script:DqeBusy $true
    }
    $script:DqeRowChanged = {
        $u = $script:DqeUi; $r = $u.Grid.SelectedItem
        $can = $r -and $r['CanExport'] -and $script:DqeSync.State -ne 'running'
        $u.BtnOne.IsEnabled = [bool]$can
        $u.BtnOne.ToolTip = if (-not $r) { 'Select an item in the list first.' }
            elseif ($r['CanExport']) { 'Save {0} ({1}) to its own archive.' -f $r['Leaf'], $r['SizeText'] }
            else { 'This item has no stored content; Defender kept only its metadata.' }
    }
    $script:DqeLoad = {
        # Several sources can be given at once, separated by semicolons or new lines.
        $u = $script:DqeUi
        $paths = @($u.TxtSource.Text -split '[;\r\n]+' | ForEach-Object { $_.Trim().Trim('"') } | Where-Object { $_ })
        if ($paths.Count -eq 0) { $u.TxtSummary.Text = 'Enter or choose a zip or folder first.'; return }
        foreach ($p in $paths) { if (-not (Test-Path -LiteralPath $p)) { $u.TxtSummary.Text = "That path does not exist: $p"; return } }
        $u.TxtSource.Text = $paths -join '; '; $u.Grid.ItemsSource = $null; $u.TxtEmpty.Visibility = 'Visible'; $u.TxtEmpty.Text = 'Reading the source...'
        & $script:DqeSay ('Loading {0}' -f ($paths -join ', '))
        $pw = @(); if ($u.TxtSrcPw.Text) { $pw = @($u.TxtSrcPw.Text) }
        & $script:DqeStart 'load' @{ Paths = $paths; Passwords = $pw }
    }
    $script:DqeOnLoaded = {
        $u = $script:DqeUi; $M = $script:DqeSync.Model
        $t = New-Object Data.DataTable
        [void]$t.Columns.Add('Sel', [bool]); [void]$t.Columns.Add('CanExport', [bool])
        foreach ($c in 'Key', 'Threat', 'Type', 'Path', 'SizeText', 'Payload', 'Detected', 'Leaf') { [void]$t.Columns.Add($c, [string]) }
        [void]$t.Columns.Add('SizeNum', [int64])
        $files = 0; $hives = 0; $missing = 0
        foreach ($r in $M.Rows) {
            $can = ($r.Payload -eq 'File' -or $r.Payload -eq 'Registry hive')
            if ($r.Payload -eq 'File') { $files++ } elseif ($r.Payload -eq 'Registry hive') { $hives++ } elseif ($r.Payload -eq 'Missing') { $missing++ }
            $sz = if ($can) { if ($r.Size -ge 1MB) { '{0:N1} MB' -f ($r.Size / 1MB) } elseif ($r.Size -ge 1KB) { '{0:N1} KB' -f ($r.Size / 1KB) } else { "$($r.Size) B" } } else { '' }
            $pay = switch ($r.Payload) { 'None' { 'Metadata only' } 'Missing' { 'Missing in source' } default { $r.Payload } }
            $lf = ([string]$r.Path -replace '->\(.*\)$', ''); $i = $lf.LastIndexOf('\'); if ($i -ge 0) { $lf = $lf.Substring($i + 1) }
            $det = if ($r.Detected.Length -ge 19) { $r.Detected.Substring(0, 19) } else { $r.Detected }
            [void]$t.Rows.Add($can, $can, $r.Key, $r.Threat, $r.Type, $r.Path, $sz, $pay, $det, $lf, [int64]$r.Size)
        }
        $script:DqeState.Table = $t; $u.Grid.ItemsSource = $t.DefaultView
        $c = $M.Counts
        if ($t.Rows.Count -eq 0) {
            $u.TxtEmpty.Visibility = 'Visible'
            $u.TxtEmpty.Text = if ($M.Src.Items.Count -eq 0) { 'The source is empty.' } else { 'No quarantine entries or payloads were found in this source. Scan history and logs can still be exported with Generate package.' }
        } else { $u.TxtEmpty.Visibility = 'Collapsed' }
        $u.TxtSummary.Text = '{0} recoverable file(s), {1} registry hive(s) in {2} quarantine entr{3}{4}.   Also found: {5} detection history, {6} scan results, {7} scan store records, {8} logs{9}.' -f `
            $files, $hives, $c['entry'], $(if ($c['entry'] -eq 1) { 'y' } else { 'ies' }), $(if ($missing) { " ($missing payload(s) missing from the source)" } else { '' }), $c['dh'], $c['result'], $c['store'], ($c['mpdet'] + $c['mplog'] + $c['evtx']),
            $(if ($c['container']) { ", inside $($c['container']) nested archive(s)" } else { '' })
        $first = [string]$M.Src.Inputs[0].path
        if (-not $u.TxtOut.Text) {
            try { $u.TxtOut.Text = [IO.Path]::GetDirectoryName($first.TrimEnd('\')) } catch { }
        }
        if (-not $u.TxtTitle.Text) {
            $nm = [IO.Path]::GetFileNameWithoutExtension(([string]$M.Src.Inputs[0].name -replace '(?i)\.gz(ip)?$', ''))
            $u.TxtTitle.Text = 'Defender quarantine extraction - ' + $nm
        }
        & $script:DqeSay ('Loaded. {0} item(s) listed.' -f $t.Rows.Count)
    }
    $script:DqeArgs = {
        $u = $script:DqeUi
        if (-not $u.TxtPassword.Text) { $u.TxtStage.Text = 'Enter an archive password first.'; return $null }
        $out = $u.TxtOut.Text.Trim().Trim('"')
        if (-not $out) { $u.TxtStage.Text = 'Choose a folder to save to first.'; return $null }
        @{ OutDir = $out; Password = $u.TxtPassword.Text; Encryption = $(if ($u.RbZc.IsChecked) { 'zipcrypto' } else { 'aes' }) }
    }
    $script:DqeTick = {
        $u = $script:DqeUi; $S = $script:DqeSync; $st = $script:DqeState
        $n = $S.Log.Count
        if ($n -gt $st.LogPos) {
            for ($i = $st.LogPos; $i -lt $n; $i++) {
                $parts = ([string]$S.Log[$i]).Split('|', 3)
                [void]$st.LogText.AppendLine(('{0}  {1}{2}' -f $parts[0], $(if ($parts[1] -ne 'info') { $parts[1].ToUpper() + '  ' } else { '' }), $parts[2]))
            }
            $st.LogPos = $n; $u.TxtLog.Text = $st.LogText.ToString(); $u.TxtLog.ScrollToEnd()
        }
        if ($S.State -eq 'running') { $u.Bar.Value = [double]$S.Pct; $u.TxtStage.Text = [string]$S.Stage; return }
        if (-not $st.Ps) { return }
        try { [void]$st.Ps.EndInvoke($st.Handle) } catch { }
        $st.Ps.Dispose(); $st.Ps = $null; $mode = $st.Mode
        if ($S.State -eq 'error') {
            $u.Bar.Value = 0
            $u.TxtStage.Text = if ($S.Error -eq 'Cancelled.') { 'Cancelled. Nothing was kept.' } else { "Stopped: $($S.Error)" }
            if ($mode -eq 'load') { $u.TxtEmpty.Visibility = 'Visible'; $u.TxtEmpty.Text = 'The source could not be loaded. See the message below.' }
        } elseif ($mode -eq 'load') {
            $u.Bar.Value = 0; $u.TxtStage.Text = 'Loaded. Fill in the case details, then generate the package.'
            & $script:DqeOnLoaded
        } else {
            $R = $S.Result; $st.Last = $R; $u.Bar.Value = 100
            if ($R.Single) { $u.TxtStage.Text = 'Saved {0} as an encrypted zip.' -f $R.Name; $u.BtnShow.Visibility = 'Visible' }
            else {
                $u.TxtStage.Text = 'Done. {0} file(s), {1} registry hive(s), {2} timeline events.{3}' -f $R.Samples, $R.Hives, $R.Events, $(if ($R.Warnings) { "  $($R.Warnings) warning(s), see the report." } else { '' })
                $u.BtnReport.Visibility = 'Visible'; $u.BtnShow.Visibility = 'Visible'
                if ($u.ChkOpen.IsChecked) { try { Start-Process -FilePath $R.Report } catch { } }
            }
        }
        $S.State = 'idle'; & $script:DqeBusy $false
        if ($S.State -eq 'idle' -and $mode -ne 'load' -and $st.Last) { $u.BtnShow.Visibility = 'Visible'; if (-not $st.Last.Single) { $u.BtnReport.Visibility = 'Visible' } }
    }

    $ui.BtnZip.Add_Click({
        $d = New-Object Microsoft.Win32.OpenFileDialog; $d.Multiselect = $true; $d.Title = 'Choose the collected archive(s)'
        $d.Filter = 'Collected archives (*.zip;*.gz)|*.zip;*.gz;*.gzip|All files (*.*)|*.*'
        if ($d.ShowDialog($script:DqeUi.Win)) { $script:DqeUi.TxtSource.Text = $d.FileNames -join '; '; & $script:DqeLoad }
    })
    $ui.BtnFolder.Add_Click({
        $d = New-Object Windows.Forms.FolderBrowserDialog; $d.ShowNewFolderButton = $false
        $d.Description = 'Choose the extracted collection. Any level works: the collection root, ProgramData, Windows Defender, Quarantine, or a folder of loose Defender files.'
        if ($d.ShowDialog() -eq 'OK') { $script:DqeUi.TxtSource.Text = $d.SelectedPath; & $script:DqeLoad }
    })
    $ui.BtnOut.Add_Click({
        $d = New-Object Windows.Forms.FolderBrowserDialog; $d.Description = 'Choose where to save the archive and report'
        if ($script:DqeUi.TxtOut.Text -and (Test-Path -LiteralPath $script:DqeUi.TxtOut.Text)) { $d.SelectedPath = $script:DqeUi.TxtOut.Text }
        if ($d.ShowDialog() -eq 'OK') { $script:DqeUi.TxtOut.Text = $d.SelectedPath }
    })
    $ui.BtnLoad.Add_Click({ & $script:DqeLoad })
    $ui.TxtSource.Add_KeyDown({ param($s, $e) if ($e.Key -eq 'Return') { & $script:DqeLoad } })
    $win.Add_DragOver({ param($s, $e) if ($e.Data.GetDataPresent([Windows.DataFormats]::FileDrop)) { $e.Effects = 'Copy' } else { $e.Effects = 'None' }; $e.Handled = $true })
    $win.Add_Drop({ param($s, $e)
        if ($script:DqeSync.State -eq 'running') { return }
        $f = $e.Data.GetData([Windows.DataFormats]::FileDrop); if ($f) { $script:DqeUi.TxtSource.Text = @($f) -join '; '; & $script:DqeLoad } })
    $ui.BtnAll.Add_Click({ if ($script:DqeState.Table) { foreach ($r in $script:DqeState.Table.Rows) { if ($r['CanExport']) { $r['Sel'] = $true } } } })
    $ui.BtnNone.Add_Click({ if ($script:DqeState.Table) { foreach ($r in $script:DqeState.Table.Rows) { $r['Sel'] = $false } } })
    $ui.Grid.Add_SelectionChanged({ & $script:DqeRowChanged })
    $menu = New-Object Windows.Controls.ContextMenu
    $mItem = New-Object Windows.Controls.MenuItem; $mItem.Header = 'Save this item as zip...'; [void]$menu.Items.Add($mItem)
    $mItem.Add_Click({ $script:DqeUi.BtnOne.RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Primitives.ButtonBase]::ClickEvent))) })
    $menu.Add_Opened({ $this.Items[0].IsEnabled = $script:DqeUi.BtnOne.IsEnabled })
    $ui.Grid.ContextMenu = $menu
    $ui.Grid.Add_PreviewMouseRightButtonDown({
        param($s, $e)
        $d = $e.OriginalSource
        while ($d -and -not ($d -is [Windows.Controls.DataGridRow])) { $d = [Windows.Media.VisualTreeHelper]::GetParent($d) }
        if ($d) { $d.IsSelected = $true }
    })
    $ui.Grid.Add_MouseDoubleClick({ if ($script:DqeUi.BtnOne.IsEnabled) { $script:DqeUi.BtnOne.RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Primitives.ButtonBase]::ClickEvent))) } })
    $ui.BtnOne.Add_Click({
        $u = $script:DqeUi; $r = $u.Grid.SelectedItem; if (-not $r) { return }
        $a = & $script:DqeArgs; if (-not $a) { return }
        $d = New-Object Microsoft.Win32.SaveFileDialog; $d.Filter = 'Zip archive (*.zip)|*.zip'; $d.Title = 'Save this file as an encrypted zip'
        $d.FileName = ([regex]::Replace([string]$r['Leaf'], '[\x00-\x1f<>:"/\\|?*]', '_')) + '.zip'
        if (Test-Path -LiteralPath $a.OutDir) { $d.InitialDirectory = $a.OutDir }
        if (-not $d.ShowDialog($u.Win)) { return }
        $a.Key = [string]$r['Key']; $a.OutPath = $d.FileName
        & $script:DqeSay "Saving $($r['Leaf']) on its own."
        & $script:DqeStart 'single' $a
    })
    $ui.BtnGo.Add_Click({
        $u = $script:DqeUi; $a = & $script:DqeArgs; if (-not $a) { return }
        $a.Selected = @(); if ($script:DqeState.Table) { $a.Selected = @($script:DqeState.Table.Rows | Where-Object { $_['Sel'] } | ForEach-Object { [string]$_['Key'] }) }
        $a.CaseId = $u.TxtCase.Text.Trim(); $a.Analyst = $u.TxtAnalyst.Text.Trim(); $a.Title = $u.TxtTitle.Text.Trim(); $a.Description = $u.TxtDesc.Text.Trim()
        $a.Raw = if ($u.RbAll.IsChecked) { 'all' } elseif ($u.RbNone.IsChecked) { 'none' } else { 'core' }
        $a.PerSample = [bool]$u.ChkPer.IsChecked; $a.Verify = [bool]$u.ChkVerify.IsChecked; $a.Template = $DqeReportTemplate
        & $script:DqeSay ('Generating package with {0} item(s) ticked.' -f $a.Selected.Count)
        & $script:DqeStart 'generate' $a
    })
    $ui.BtnCancel.Add_Click({ $script:DqeSync.Cancel = $true; $script:DqeUi.TxtStage.Text = 'Cancelling...' })
    $ui.BtnReport.Add_Click({ $l = $script:DqeState.Last; if ($l -and $l.Report) { try { Start-Process -FilePath $l.Report } catch { } } })
    $ui.BtnShow.Add_Click({ $l = $script:DqeState.Last; if ($l -and $l.Zip) { try { Start-Process explorer.exe -ArgumentList ('/select,"{0}"' -f $l.Zip) } catch { } } })

    $timer = New-Object Windows.Threading.DispatcherTimer; $timer.Interval = [TimeSpan]::FromMilliseconds(150)
    $timer.Add_Tick({ try { & $script:DqeTick } catch { $script:DqeUi.TxtStage.Text = "Interface error: $($_.Exception.Message)" } })
    $script:DqeState.Timer = $timer
    $win.Add_ContentRendered({ $script:DqeState.Timer.Start() })
    $win.Add_Closed({
        try { $script:DqeState.Timer.Stop() } catch { }
        $script:DqeSync.Cancel = $true
        try { if ($script:DqeState.Ps) { $script:DqeState.Ps.Stop(); $script:DqeState.Ps.Dispose() } } catch { }
        try { if ($script:DqeSync.Model) { foreach ($h in $script:DqeSync.Model.Src.Handles) { $h.Dispose() } } } catch { }
        try { $script:DqeState.Rs.Close(); $script:DqeState.Rs.Dispose() } catch { }
    })
    $win
}
