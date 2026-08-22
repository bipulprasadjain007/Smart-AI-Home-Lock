import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:image_picker/image_picker.dart';

import '../../core/validation/validators.dart';
import '../../data/services/smart_lock_api.dart';
import '../widgets/common.dart';

class EnrollmentScreen extends StatefulWidget {
  const EnrollmentScreen({required this.api, super.key});

  final SmartLockApi api;

  @override
  State<EnrollmentScreen> createState() => _EnrollmentScreenState();
}

class _EnrollmentScreenState extends State<EnrollmentScreen> {
  static const int _photoCount = 5;
  static const int _maxBytes = 2 * 1024 * 1024;

  final GlobalKey<FormState> _formKey = GlobalKey<FormState>();
  final TextEditingController _userId = TextEditingController();
  final TextEditingController _pin = TextEditingController();
  final TextEditingController _confirmPin = TextEditingController();
  final ImagePicker _picker = ImagePicker();
  final List<EnrollmentPhoto?> _photos = List<EnrollmentPhoto?>.filled(
    _photoCount,
    null,
  );
  bool _busy = false;
  bool _setPinAfterEnrollment = true;

  @override
  void initState() {
    super.initState();
    _recoverLostImages();
  }

  @override
  void dispose() {
    _userId.dispose();
    _pin.dispose();
    _confirmPin.dispose();
    super.dispose();
  }

  Future<void> _recoverLostImages() async {
    final LostDataResponse response = await _picker.retrieveLostData();
    final List<XFile>? files = response.files;
    if (files == null || files.isEmpty || !mounted) {
      return;
    }
    for (final XFile file in files.take(_photoCount)) {
      final int slot = _photos.indexOf(null);
      if (slot == -1) {
        break;
      }
      await _storePhoto(slot, file);
    }
  }

  Future<void> _choosePhoto(int index) async {
    final ImageSource? source = await showModalBottomSheet<ImageSource>(
      context: context,
      showDragHandle: true,
      builder: (BuildContext context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: <Widget>[
            ListTile(
              leading: const Icon(Icons.camera_alt_outlined),
              title: const Text('Take photo'),
              onTap: () => Navigator.pop(context, ImageSource.camera),
            ),
            ListTile(
              leading: const Icon(Icons.photo_library_outlined),
              title: const Text('Choose from gallery'),
              onTap: () => Navigator.pop(context, ImageSource.gallery),
            ),
          ],
        ),
      ),
    );
    if (source == null) {
      return;
    }
    final XFile? file = await _picker.pickImage(
      source: source,
      preferredCameraDevice: CameraDevice.front,
      maxWidth: 1280,
      maxHeight: 1280,
      imageQuality: 82,
      requestFullMetadata: false,
    );
    if (file != null) {
      await _storePhoto(index, file);
    }
  }

  Future<void> _storePhoto(int index, XFile file) async {
    final Uint8List bytes = await file.readAsBytes();
    if (!mounted) {
      return;
    }
    if (bytes.isEmpty || bytes.length > _maxBytes) {
      _show('Photo must be a non-empty JPEG or PNG under 2 MB.');
      return;
    }
    setState(() {
      _photos[index] = EnrollmentPhoto(
        bytes: bytes,
        filename: file.name.isEmpty ? 'image${index + 1}.jpg' : file.name,
      );
    });
  }

  Future<void> _submit() async {
    if (!_formKey.currentState!.validate()) {
      return;
    }
    if (_photos.any((EnrollmentPhoto? photo) => photo == null)) {
      _show('Capture all five face angles before enrolling.');
      return;
    }
    setState(() => _busy = true);
    try {
      final String userId = _userId.text.trim();
      await widget.api.registerUser(
        userId,
        _photos.cast<EnrollmentPhoto>(),
      );
      if (_setPinAfterEnrollment) {
        await widget.api.setPin(userId, _pin.text);
      }
      if (mounted) {
        _show('User $userId enrolled successfully.');
        _formKey.currentState!.reset();
        _userId.clear();
        _pin.clear();
        _confirmPin.clear();
        setState(() {
          for (int index = 0; index < _photos.length; index++) {
            _photos[index] = null;
          }
        });
      }
    } catch (error) {
      if (mounted) {
        _show(error.toString());
      }
    } finally {
      if (mounted) {
        setState(() => _busy = false);
      }
    }
  }

  void _show(String message) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(message)));
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.fromLTRB(20, 12, 20, 32),
      children: <Widget>[
        const PageIntro(
          title: 'Enroll a user',
          description: 'Capture five clear angles. Images are processed in memory and are not stored by the app.',
        ),
        const SizedBox(height: 20),
        Form(
          key: _formKey,
          child: Column(
            children: <Widget>[
              SectionCard(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: <Widget>[
                    TextFormField(
                      controller: _userId,
                      enabled: !_busy,
                      validator: validateUserId,
                      autocorrect: false,
                      decoration: const InputDecoration(
                        labelText: 'User ID',
                        helperText: 'Example: bipul_home',
                        prefixIcon: Icon(Icons.person_outline),
                      ),
                    ),
                    const SizedBox(height: 18),
                    Text('Required face angles', style: Theme.of(context).textTheme.titleMedium),
                    const SizedBox(height: 4),
                    const Text('Use even lighting, one face per image, and no sunglasses.'),
                    const SizedBox(height: 16),
                    GridView.builder(
                      shrinkWrap: true,
                      physics: const NeverScrollableScrollPhysics(),
                      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                        crossAxisCount: 2,
                        mainAxisSpacing: 12,
                        crossAxisSpacing: 12,
                        childAspectRatio: 1.05,
                      ),
                      itemCount: _photoCount,
                      itemBuilder: (BuildContext context, int index) {
                        return _PhotoSlot(
                          index: index,
                          photo: _photos[index],
                          onTap: _busy ? null : () => _choosePhoto(index),
                          onRemove: _busy
                              ? null
                              : () => setState(() => _photos[index] = null),
                        );
                      },
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),
              SectionCard(
                child: Column(
                  children: <Widget>[
                    SwitchListTile.adaptive(
                      contentPadding: EdgeInsets.zero,
                      title: const Text('Set a PIN after enrollment'),
                      subtitle: const Text('The PIN is sent only over the authenticated HTTPS session.'),
                      value: _setPinAfterEnrollment,
                      onChanged: _busy
                          ? null
                          : (bool value) => setState(() => _setPinAfterEnrollment = value),
                    ),
                    if (_setPinAfterEnrollment) ...<Widget>[
                      const SizedBox(height: 8),
                      TextFormField(
                        controller: _pin,
                        enabled: !_busy,
                        validator: validatePin,
                        keyboardType: TextInputType.number,
                        obscureText: true,
                        maxLength: 6,
                        inputFormatters: <TextInputFormatter>[FilteringTextInputFormatter.digitsOnly],
                        decoration: const InputDecoration(labelText: 'Six-digit PIN'),
                      ),
                      const SizedBox(height: 12),
                      TextFormField(
                        controller: _confirmPin,
                        enabled: !_busy,
                        validator: (String? value) {
                          final String? formatError = validatePin(value);
                          if (formatError != null) {
                            return formatError;
                          }
                          return value == _pin.text ? null : 'PINs do not match.';
                        },
                        keyboardType: TextInputType.number,
                        obscureText: true,
                        maxLength: 6,
                        inputFormatters: <TextInputFormatter>[FilteringTextInputFormatter.digitsOnly],
                        decoration: const InputDecoration(labelText: 'Confirm PIN'),
                      ),
                    ],
                  ],
                ),
              ),
              const SizedBox(height: 20),
              SizedBox(
                width: double.infinity,
                child: FilledButton.icon(
                  onPressed: _busy ? null : _submit,
                  icon: _busy
                      ? const SizedBox.square(
                          dimension: 18,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.person_add_alt_1),
                  label: const Text('Enroll user'),
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }
}

class _PhotoSlot extends StatelessWidget {
  const _PhotoSlot({
    required this.index,
    required this.photo,
    required this.onTap,
    required this.onRemove,
  });

  static const List<String> _labels = <String>[
    'Front',
    'Slight left',
    'Slight right',
    'Chin up',
    'Chin down',
  ];

  final int index;
  final EnrollmentPhoto? photo;
  final VoidCallback? onTap;
  final VoidCallback? onRemove;

  @override
  Widget build(BuildContext context) {
    return Material(
      color: const Color(0xFFF8FAFC),
      borderRadius: BorderRadius.circular(16),
      clipBehavior: Clip.antiAlias,
      child: InkWell(
        onTap: onTap,
        child: Stack(
          fit: StackFit.expand,
          children: <Widget>[
            if (photo != null)
              Image.memory(photo!.bytes, fit: BoxFit.cover, gaplessPlayback: true)
            else
              Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: <Widget>[
                  const Icon(Icons.add_a_photo_outlined, size: 32),
                  const SizedBox(height: 8),
                  Text(_labels[index]),
                ],
              ),
            Positioned(
              left: 8,
              bottom: 8,
              child: Chip(
                visualDensity: VisualDensity.compact,
                label: Text(_labels[index]),
              ),
            ),
            if (photo != null)
              Positioned(
                right: 4,
                top: 4,
                child: IconButton.filledTonal(
                  tooltip: 'Remove ${_labels[index]} photo',
                  onPressed: onRemove,
                  icon: const Icon(Icons.close),
                ),
              ),
          ],
        ),
      ),
    );
  }
}
