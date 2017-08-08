using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
namespace inVteroUI
{


    [RefreshProperties(RefreshProperties.All)]
        public class DictionaryAdapter<T, U> : ICustomTypeDescriptor, INotifyPropertyChanged
        {
            #region Fields

            private readonly IDictionary<T, U> dictionary;

            #endregion

            #region Constructors and Destructors

            public DictionaryAdapter(IDictionary<T, U> dictionary)
            {
                this.dictionary = dictionary;
            }

            #endregion

            #region Events

            public event PropertyChangedEventHandler PropertyChanged;

            #endregion

            [Browsable(false)]
            public U this[T key]
            {
                get
                {
                    return this.dictionary[key];
                }
                set
                {
                    this.dictionary[key] = value;
                }
            }

            public AttributeCollection GetAttributes()
            {
                return TypeDescriptor.GetAttributes(this, true);
            }

            public string GetClassName()
            {
                return TypeDescriptor.GetClassName(this, true);
            }

            public string GetComponentName()
            {
                return TypeDescriptor.GetComponentName(this, true);
            }

            public TypeConverter GetConverter()
            {
                return TypeDescriptor.GetConverter(this, true);
            }

            public EventDescriptor GetDefaultEvent()
            {
                return TypeDescriptor.GetDefaultEvent(this, true);
            }

            public PropertyDescriptor GetDefaultProperty()
            {
                return null;
            }

            public object GetEditor(Type editorBaseType)
            {
                return TypeDescriptor.GetEditor(this, editorBaseType, true);
            }

            public EventDescriptorCollection GetEvents(Attribute[] attributes)
            {
                return TypeDescriptor.GetEvents(this, attributes, true);
            }

            public PropertyDescriptorCollection GetProperties(Attribute[] attributes)
            {
                ArrayList properties = new ArrayList();
                foreach (var e in this.dictionary)
                {
                    properties.Add(new DictionaryPropertyDescriptor(this.dictionary, e.Key));
                }

                PropertyDescriptor[] props = (PropertyDescriptor[])properties.ToArray(typeof(PropertyDescriptor));

                return new PropertyDescriptorCollection(props);
            }

            public object GetPropertyOwner(PropertyDescriptor pd)
            {
                return this;
            }

            EventDescriptorCollection ICustomTypeDescriptor.GetEvents()
            {
                return TypeDescriptor.GetEvents(this, true);
            }

            PropertyDescriptorCollection ICustomTypeDescriptor.GetProperties()
            {
                return ((ICustomTypeDescriptor)this).GetProperties(new Attribute[0]);
            }

            protected virtual void OnPropertyChanged([CallerMemberName] string propertyName = null)
            {
                this.PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
            }

            public class DictionaryPropertyDescriptor : PropertyDescriptor
            {
                #region Fields

                private readonly IDictionary<T, U> dictionary;

                private readonly T key;

                #endregion

                #region Constructors and Destructors

                internal DictionaryPropertyDescriptor(IDictionary<T, U> dictionary, T key)
                    : base(key.ToString(), null)
                {
                    this.dictionary = dictionary;
                    this.key = key;
                }

                #endregion

                public override Type ComponentType => null;

                public override bool IsReadOnly => false;

                public override Type PropertyType => this.dictionary[this.key].GetType();

                public override bool CanResetValue(object component)
                {
                    return false;
                }

                public override object GetValue(object component)
                {
                    return this.dictionary[this.key];
                }

                public override void ResetValue(object component)
                {

                }

                public override void SetValue(object component, object value)
                {
                    this.dictionary[this.key] = (U)value;
                }

                public override bool ShouldSerializeValue(object component)
                {
                    return false;
                }
            }
        }
}
